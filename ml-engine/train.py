import argparse
import json
import os
import torch
from torch.utils.data import DataLoader
from transformers import AutoTokenizer, get_linear_schedule_with_warmup
from torch.optim import AdamW
from pathlib import Path
from utils.logging_utils import setup_logger
from utils.db import init_db
from preprocessing.data_loader import load_dataset_from_db, prepare_splits, tokenize_data, train_cwe_classifier
from dataset.vulnerability_dataset import VulnerabilityDataset
from models.codebert_classifier import CodeBERTClassifier
from config import DB_PATH, MODEL_CHECKPOINT, SAVED_MODEL_DIR, BATCH_SIZE, EPOCHS, LEARNING_RATE, MAX_TRAIN_SAMPLES

logger = setup_logger("train-pipeline")

def write_status(status: str, epoch: int = 0, loss: float = 0.0, val_loss: float = 0.0, val_acc: float = 0.0, val_f1: float = 0.0, test_metrics: dict = None, error: str = None) -> None:
    """Writes the current training status to a JSON file for monitoring via the health API."""
    import config as cfg
    status_path = Path(SAVED_MODEL_DIR) / "train_status.json"
    status_data = {
        "status": status,
        "epoch": epoch,
        "total_epochs": cfg.EPOCHS,
        "loss": round(loss, 4),
        "val_loss": round(val_loss, 4),
        "val_acc": round(val_acc, 4),
        "val_f1": round(val_f1, 4),
        "error": error
    }
    if test_metrics:
        status_data["test_metrics"] = {k: round(v, 4) if isinstance(v, float) else v for k, v in test_metrics.items()}
    try:
        with open(status_path, "w") as f:
            json.dump(status_data, f, indent=2)
    except Exception as e:
        logger.error(f"Failed to write training status: {e}")

def compute_metrics(logits: torch.Tensor, labels: torch.Tensor) -> tuple:
    """Computes basic accuracy, precision, recall, and F1 score."""
    preds = torch.argmax(logits, dim=1)
    
    # Accuracy
    correct = (preds == labels).sum().item()
    acc = correct / len(labels) if len(labels) > 0 else 0.0
    
    # Binary metrics
    tp = ((preds == 1) & (labels == 1)).sum().item()
    fp = ((preds == 1) & (labels == 0)).sum().item()
    fn = ((preds == 0) & (labels == 1)).sum().item()
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    
    return acc, f1

def run_train_pipeline() -> None:
    """Executes the training pipeline from database loading to model evaluation with performance optimizations."""
    import config as cfg  # read at call time so CLI overrides propagate
    epochs = cfg.EPOCHS
    batch_size = cfg.BATCH_SIZE
    lr = cfg.LEARNING_RATE
    max_samples = cfg.MAX_TRAIN_SAMPLES

    logger.info(f"Initializing ML Engine Training Pipeline (epochs={epochs}, max_samples={max_samples}, batch_size={batch_size}, lr={lr})...")
    write_status("starting")
    
    try:
        # 1. Setup DB if not already setup
        init_db(force=False)
        
        # 2. Load dataset
        df = load_dataset_from_db(str(DB_PATH), max_samples)
        if len(df) == 0:
            raise ValueError("No training data loaded from database.")
            
        # 3. Train CWE Classifier (TF-IDF + Random Forest)
        train_cwe_classifier(df, Path(SAVED_MODEL_DIR))
        
        # 4. Tokenize & Prepare Datasets
        logger.info(f"Loading tokenizer: {MODEL_CHECKPOINT}...")
        tokenizer = AutoTokenizer.from_pretrained(MODEL_CHECKPOINT)
        
        train_df, val_df, test_df = prepare_splits(df)
        
        logger.info("Tokenizing splits...")
        train_encodings = tokenize_data(train_df['code'].tolist(), tokenizer)
        val_encodings = tokenize_data(val_df['code'].tolist(), tokenizer)
        test_encodings = tokenize_data(test_df['code'].tolist(), tokenizer)
        
        train_dataset = VulnerabilityDataset(train_encodings, train_df['label'].tolist())
        val_dataset = VulnerabilityDataset(val_encodings, val_df['label'].tolist())
        test_dataset = VulnerabilityDataset(test_encodings, test_df['label'].tolist())
        
        # CPU/GPU loader optimization
        num_workers = min(4, os.cpu_count() or 1) if os.name != 'nt' else 0 # num_workers > 0 on Windows can cause pickle issues
        pin_memory = torch.cuda.is_available()
        
        train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True, num_workers=num_workers, pin_memory=pin_memory)
        val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False, num_workers=num_workers, pin_memory=pin_memory)
        test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False, num_workers=num_workers, pin_memory=pin_memory)
        
        # 5. Initialize Model
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        logger.info(f"Training on device: {device}")
        
        model = CodeBERTClassifier(MODEL_CHECKPOINT)
        model.to(device)
        
        # 6. Training Loop & Optimizations
        optimizer = AdamW(model.parameters(), lr=lr, weight_decay=0.01)
        
        # Warmup and Linear schedule
        total_steps = len(train_loader) * epochs
        num_warmup_steps = int(0.1 * total_steps) # 10% warmup
        scheduler = get_linear_schedule_with_warmup(optimizer, num_warmup_steps=num_warmup_steps, num_training_steps=total_steps)
        
        # AMP (Automatic Mixed Precision)
        use_amp = device.type == "cuda"
        scaler = torch.amp.GradScaler(device.type) if use_amp else None
        
        best_val_f1 = -1.0
        early_stopping_patience = 2
        no_improvement_epochs = 0
        
        # Gradient Accumulation
        grad_accum_steps = 2 if batch_size < 16 else 1
        
        write_status("running", epoch=0)
        
        for epoch in range(1, epochs + 1):
            model.train()
            total_train_loss = 0.0
            logger.info(f"Starting Epoch {epoch}/{epochs}...")
            
            optimizer.zero_grad()
            for step, batch in enumerate(train_loader, 1):
                input_ids = batch['input_ids'].to(device, non_blocking=True)
                attention_mask = batch['attention_mask'].to(device, non_blocking=True)
                labels = batch['labels'].to(device, non_blocking=True)
                
                # Forward pass with AMP autocast
                with torch.amp.autocast(device_type=device.type, enabled=use_amp):
                    loss, logits, _ = model(input_ids, attention_mask, labels)
                    loss = loss / grad_accum_steps
                
                # Backward pass
                if scaler:
                    scaler.scale(loss).backward()
                else:
                    loss.backward()
                
                if step % grad_accum_steps == 0 or step == len(train_loader):
                    if scaler:
                        scaler.unscale_(optimizer)
                        torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
                        scaler.step(optimizer)
                        scaler.update()
                    else:
                        torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
                        optimizer.step()
                    
                    scheduler.step()
                    optimizer.zero_grad()
                
                total_train_loss += loss.item() * grad_accum_steps
                
                if step % 20 == 0 or step == len(train_loader):
                    logger.info(f"Epoch {epoch} | Step {step}/{len(train_loader)} | Batch Loss: {loss.item() * grad_accum_steps:.4f}")
            
            avg_train_loss = total_train_loss / len(train_loader)
            
            # Validation loop
            model.eval()
            total_val_loss = 0.0
            all_val_logits = []
            all_val_labels = []
            
            logger.info("Running validation...")
            with torch.no_grad():
                for batch in val_loader:
                    input_ids = batch['input_ids'].to(device, non_blocking=True)
                    attention_mask = batch['attention_mask'].to(device, non_blocking=True)
                    labels = batch['labels'].to(device, non_blocking=True)
                    
                    with torch.amp.autocast(device_type=device.type, enabled=use_amp):
                        loss, logits, _ = model(input_ids, attention_mask, labels)
                    
                    total_val_loss += loss.item()
                    all_val_logits.append(logits.cpu())
                    all_val_labels.append(labels.cpu())
            
            avg_val_loss = total_val_loss / len(val_loader)
            val_logits = torch.cat(all_val_logits, dim=0)
            val_labels = torch.cat(all_val_labels, dim=0)
            
            val_acc, val_f1 = compute_metrics(val_logits, val_labels)
            
            logger.info(f"Epoch {epoch} Results | Train Loss: {avg_train_loss:.4f} | Val Loss: {avg_val_loss:.4f} | Val Acc: {val_acc:.4f} | Val F1: {val_f1:.4f}")
            write_status("running", epoch=epoch, loss=avg_train_loss, val_loss=avg_val_loss, val_acc=val_acc, val_f1=val_f1)
            
            # Checkpoint saving & early stopping check
            if val_f1 > best_val_f1:
                best_val_f1 = val_f1
                no_improvement_epochs = 0
                logger.info(f"New best F1 score: {best_val_f1:.4f}. Saving best model checkpoint...")
                best_model_path = Path(SAVED_MODEL_DIR) / "best_model"
                model.save_pretrained(str(best_model_path))
                tokenizer.save_pretrained(str(best_model_path))
            else:
                no_improvement_epochs += 1
                logger.info(f"No validation improvement for {no_improvement_epochs} epoch(s). Best F1: {best_val_f1:.4f}")
                if no_improvement_epochs >= early_stopping_patience:
                    logger.warning(f"Early stopping triggered after {epoch} epochs of no improvement.")
                    break
        
        # 7. Final Model Evaluation on Hold-out Test Set
        logger.info("Loading best model for final evaluation on test set...")
        best_model_path = Path(SAVED_MODEL_DIR) / "best_model"
        if best_model_path.exists():
            model = CodeBERTClassifier.from_pretrained(str(best_model_path))
            model.to(device)
        
        model.eval()
        all_test_logits = []
        all_test_labels = []
        with torch.no_grad():
            for batch in test_loader:
                input_ids = batch['input_ids'].to(device, non_blocking=True)
                attention_mask = batch['attention_mask'].to(device, non_blocking=True)
                labels = batch['labels'].to(device, non_blocking=True)
                with torch.amp.autocast(device_type=device.type, enabled=use_amp):
                    _, logits, _ = model(input_ids, attention_mask, labels)
                all_test_logits.append(logits.cpu())
                all_test_labels.append(labels.cpu())
        
        test_logits = torch.cat(all_test_logits, dim=0)
        test_labels = torch.cat(all_test_labels, dim=0)
        test_acc, test_f1 = compute_metrics(test_logits, test_labels)
        test_metrics = {"test_accuracy": test_acc, "test_f1": test_f1}
        logger.info(f"Test Set Evaluation | Accuracy: {test_acc:.4f} | F1 Score: {test_f1:.4f}")
        
        logger.info("Training pipeline completed successfully.")
        write_status("completed", epoch=epoch, val_f1=best_val_f1, test_metrics=test_metrics)
        
    except Exception as e:
        logger.error(f"Training pipeline failed with error: {e}")
        write_status("failed", error=str(e))
        raise e

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RepoShield ML Engine Training Pipeline")
    parser.add_argument("--max-samples", type=int, default=MAX_TRAIN_SAMPLES,
                        help=f"Maximum training samples (default: {MAX_TRAIN_SAMPLES})")
    parser.add_argument("--epochs", type=int, default=EPOCHS,
                        help=f"Number of training epochs (default: {EPOCHS})")
    parser.add_argument("--lr", type=float, default=LEARNING_RATE,
                        help=f"Learning rate (default: {LEARNING_RATE})")
    parser.add_argument("--batch-size", type=int, default=BATCH_SIZE,
                        help=f"Batch size (default: {BATCH_SIZE})")
    args = parser.parse_args()
    
    # Override module-level config with CLI args
    import config
    config.MAX_TRAIN_SAMPLES = args.max_samples
    config.EPOCHS = args.epochs
    config.LEARNING_RATE = args.lr
    config.BATCH_SIZE = args.batch_size
    
    run_train_pipeline()
