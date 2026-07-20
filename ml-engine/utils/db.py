import sqlite3
from pathlib import Path
from utils.logging_utils import setup_logger
from config import CVEFIXES_SQL_PATH, DB_PATH

logger = setup_logger("db-utils")

def parse_sql_values(values_str: str) -> list:
    """Parses a SQL values string (the part inside the outermost parentheses of an INSERT statement)
    into a list of string tokens, handling escaped single quotes ('') and NULL values.
    
    Example:
        parse_sql_values("123, 'hello ''world''', NULL")
        -> ["123", "hello 'world'", "NULL"]
    """
    tokens = []
    in_quote = False
    current = []
    i = 0
    n = len(values_str)
    while i < n:
        c = values_str[i]
        if in_quote:
            if c == "'":
                if i + 1 < n and values_str[i + 1] == "'":
                    current.append("'")
                    i += 2
                else:
                    in_quote = False
                    tokens.append("".join(current))  # quoted content; no strip needed
                    current = []
                    i += 1
            else:
                current.append(c)
                i += 1
        else:
            if c == "'":
                # discard any leading whitespace before the opening quote
                current = []
                in_quote = True
                i += 1
            elif c == ",":
                val = "".join(current).strip()
                if val:
                    tokens.append(val)
                current = []
                i += 1
            else:
                current.append(c)
                i += 1
    # Final token
    val = "".join(current).strip()
    if val:
        tokens.append(val)
    return tokens

def extract_file_change_fields(line: str) -> tuple:
    """Fast extraction of first 3 columns and programming language from file_change insert lines."""
    val_start = line.find('VALUES')
    if val_start == -1:
        return None
    
    # Find the opening parenthesis
    paren_idx = line.find('(', val_start)
    if paren_idx == -1:
        return None
        
    # We take the first 1000 characters after '(' which covers the first 3 columns
    start_part = line[paren_idx + 1: paren_idx + 1000]
    
    # Parse the first 3 columns with escape-aware parsing
    tokens = []
    in_quote = False
    current = []
    i = 0
    n = len(start_part)
    while i < n:
        c = start_part[i]
        if in_quote:
            if c == "'":
                if i + 1 < n and start_part[i+1] == "'":
                    current.append("'")
                    i += 2
                else:
                    in_quote = False
                    tokens.append("".join(current))
                    current = []
                    i += 1
                    if len(tokens) >= 3:
                        break
            else:
                current.append(c)
                i += 1
        else:
            if c == "'":
                in_quote = True
                i += 1
            else:
                i += 1
                
    if len(tokens) < 3:
        return None
        
    file_change_id, file_hash, filename = tokens[0], tokens[1], tokens[2]
    
    # Extract programming language from the end of the line
    end_idx = line.rfind(')')
    if end_idx == -1:
        return None
        
    # Take the last 200 characters before ')'
    last_part = line[max(0, end_idx - 200):end_idx]
    # Split by comma
    end_tokens = last_part.split(',')
    if len(end_tokens) >= 3:
        programming_language = end_tokens[-3].strip().strip("'")
        if programming_language == "NULL":
            programming_language = ""
    else:
        programming_language = ""
        
    filename = filename.replace("'", "''")
    return file_change_id, file_hash, filename, programming_language

def init_db(force: bool = False) -> None:
    """Imports the CVEfixes SQL dump into a local SQLite database with optimizations."""
    if Path(DB_PATH).exists() and not force:
        logger.info(f"Database already exists at {DB_PATH}. Skipping import.")
        return

    sql_path = Path(CVEFIXES_SQL_PATH)
    if not sql_path.exists():
        raise FileNotFoundError(f"CVEfixes SQL dump not found at {sql_path}")

    logger.info(f"Starting database initialization. Reading from {sql_path}...")
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    
    if not Path(DB_PATH).exists():
        from dataset.download_dataset import download_dataset
        download_dataset()

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # SQLite optimization settings
    cursor.execute("PRAGMA journal_mode = OFF;")
    cursor.execute("PRAGMA synchronous = OFF;")
    cursor.execute("PRAGMA cache_size = 200000;")
    cursor.execute("PRAGMA temp_store = MEMORY;")
    
    # We will buffer statements and commit in chunks
    batch_size = 5000
    pending_statements = []
    
    # Tables we want to import
    allowed_tables = {"fixes", "commits", "cve", "cwe_classification", "cwe", "method_change", "file_change", "repository"}
    
    logger.info("Parsing SQL dump and importing data...")
    
    count = 0
    with open(sql_path, "r", encoding="utf-8") as f:
        in_create = False
        create_buffer = []
        in_insert = False
        insert_buffer = []
        
        for line in f:
            line_str = line.strip()
            if not line_str:
                continue
                
            # Handle table creation blocks
            if line_str.startswith("CREATE TABLE"):
                in_create = True
                create_buffer.append(line)
                if line_str.endswith(");"):
                    cursor.execute("".join(create_buffer))
                    create_buffer = []
                    in_create = False
                continue
            elif in_create:
                create_buffer.append(line)
                if line_str.endswith(");"):
                    cursor.execute("".join(create_buffer))
                    create_buffer = []
                    in_create = False
                continue
                
            # Handle insert statements
            if line_str.startswith("INSERT INTO"):
                if not line_str.endswith(";"):
                    in_insert = True
                    insert_buffer = [line]
                    continue
                
                # Single-line insert
                stmt = line_str
                parts = line_str.split(maxsplit=3)
                if len(parts) >= 3:
                    table_name = parts[2].replace('"', '')
                    if table_name not in allowed_tables:
                        continue
                        
                    if table_name == "file_change":
                        fields = extract_file_change_fields(line_str)
                        if fields:
                            file_change_id, file_hash, filename, programming_language = fields
                            stmt = f"INSERT INTO file_change VALUES('{file_change_id}', '{file_hash}', '{filename}', '', '', '', '', '', '', '', '', '', '', '{programming_language}', '', '');"
                        else:
                            continue
                            
                    pending_statements.append(stmt)
                    count += 1
                    
                    if len(pending_statements) >= batch_size:
                        cursor.execute("BEGIN TRANSACTION;")
                        for s in pending_statements:
                            try:
                                cursor.execute(s)
                            except Exception as e:
                                logger.error(f"Insert error: {e} | Query: {s[:120]}...")
                        conn.commit()
                        pending_statements = []
                        logger.info(f"Imported {count} rows...")
                continue
                
            elif in_insert:
                insert_buffer.append(line)
                if line_str.endswith(";"):
                    stmt = "".join(insert_buffer).strip()
                    insert_buffer = []
                    in_insert = False
                    
                    clean_stmt = stmt.replace('\n', ' ').replace('\r', ' ')
                    parts = clean_stmt.split(maxsplit=3)
                    if len(parts) >= 3:
                        table_name = parts[2].replace('"', '')
                        if table_name not in allowed_tables:
                            continue
                            
                        if table_name == "file_change":
                            fields = extract_file_change_fields(clean_stmt)
                            if fields:
                                file_change_id, file_hash, filename, programming_language = fields
                                stmt = f"INSERT INTO file_change VALUES('{file_change_id}', '{file_hash}', '{filename}', '', '', '', '', '', '', '', '', '', '', '{programming_language}', '', '');"
                            else:
                                continue
                                
                        pending_statements.append(stmt)
                        count += 1
                        
                        if len(pending_statements) >= batch_size:
                            cursor.execute("BEGIN TRANSACTION;")
                            for s in pending_statements:
                                try:
                                    cursor.execute(s)
                                except Exception as e:
                                    logger.error(f"Insert error: {e} | Query: {s[:120]}...")
                            conn.commit()
                            pending_statements = []
                            logger.info(f"Imported {count} rows...")
                continue
                
    # Commit any remaining statements
    if pending_statements:
        cursor.execute("BEGIN TRANSACTION;")
        for s in pending_statements:
            try:
                cursor.execute(s)
            except Exception as e:
                logger.error(f"Insert error in final batch: {e} | Query: {s[:120]}...")
        conn.commit()
        
    logger.info(f"Database import complete. Total rows processed: {count}")
    
    # Create indexes to speed up future training data queries
    logger.info("Creating database indexes...")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_method_file ON method_change(file_change_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_file_hash ON file_change(hash);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_fixes_hash ON fixes(hash);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_fixes_cve ON fixes(cve_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cwe_class_cve ON cwe_classification(cve_id);")
    conn.close()
    logger.info("Database index creation complete.")

if __name__ == "__main__":
    init_db(force=True)
