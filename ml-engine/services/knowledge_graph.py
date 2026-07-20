from typing import List, Dict, Optional
from utils.logging_utils import setup_logger

logger = setup_logger("knowledge-graph")


class SecurityKnowledgeGraph:
    """Graph structure modeling relationships between CWEs, OWASP Top 10, regulatory standards, and mitigations."""

    def __init__(self):
        # Nodes: type -> id -> attributes
        self.nodes: Dict[str, Dict[str, Dict]] = {
            "CWE": {},
            "OWASP": {},
            "COMPLIANCE": {},
            "MITIGATION": {}
        }
        # Edges: source_id -> target_id -> relation_type
        self.edges: Dict[str, Dict[str, str]] = {}
        
        self._initialize_graph()

    def _add_node(self, node_type: str, node_id: str, attributes: Dict) -> None:
        if node_type in self.nodes:
            self.nodes[node_type][node_id] = attributes

    def _add_edge(self, source_id: str, target_id: str, relation: str) -> None:
        if source_id not in self.edges:
            self.edges[source_id] = {}
        self.edges[source_id][target_id] = relation

    def _initialize_graph(self) -> None:
        """Seeds the knowledge graph with security relationships."""
        logger.info("Initializing Security Knowledge Graph...")

        # CWE Nodes
        self._add_node("CWE", "CWE-89", {"name": "SQL Injection", "severity": "Critical"})
        self._add_node("CWE", "CWE-78", {"name": "OS Command Injection", "severity": "Critical"})
        self._add_node("CWE", "CWE-798", {"name": "Hardcoded Credentials", "severity": "High"})
        self._add_node("CWE", "CWE-22", {"name": "Path Traversal", "severity": "High"})
        self._add_node("CWE", "CWE-79", {"name": "Cross-site Scripting", "severity": "High"})
        self._add_node("CWE", "CWE-502", {"name": "Deserialization", "severity": "Critical"})

        # OWASP Nodes
        self._add_node("OWASP", "A01:2021", {"name": "Broken Access Control"})
        self._add_node("OWASP", "A03:2021", {"name": "Injection"})
        self._add_node("OWASP", "A07:2021", {"name": "Identification and Authentication Failures"})
        self._add_node("OWASP", "A08:2021", {"name": "Software and Data Integrity Failures"})

        # Compliance Nodes
        self._add_node("COMPLIANCE", "PCI-DSS-6.2.4", {"name": "PCI-DSS v4.0 Req 6.2.4 - Injection Protection"})
        self._add_node("COMPLIANCE", "PCI-DSS-3.2", {"name": "PCI-DSS v4.0 Req 3.2 - Secret Management"})
        self._add_node("COMPLIANCE", "SOC2-CC7.1", {"name": "SOC2 CC7.1 - Boundary Protection"})
        self._add_node("COMPLIANCE", "HIPAA-164.312", {"name": "HIPAA 45 CFR 164.312 - Encryption"})

        # Mitigation Nodes
        self._add_node("MITIGATION", "M-PARAM", {"desc": "Use prepared statements / parameterized bindings."})
        self._add_node("MITIGATION", "M-ENV", {"desc": "Store credentials outside source trees in environment context."})
        self._add_node("MITIGATION", "M-SAN", {"desc": "Enforce canonical target sandbox path checks."})

        # Edges (Relationships)
        # CWE -> OWASP mapping
        self._add_edge("CWE-89", "A03:2021", "classified_under")
        self._add_edge("CWE-78", "A03:2021", "classified_under")
        self._add_edge("CWE-798", "A07:2021", "classified_under")
        self._add_edge("CWE-22", "A01:2021", "classified_under")
        self._add_edge("CWE-79", "A03:2021", "classified_under")
        self._add_edge("CWE-502", "A08:2021", "classified_under")

        # CWE -> Compliance mapping
        self._add_edge("CWE-89", "PCI-DSS-6.2.4", "violates")
        self._add_edge("CWE-78", "PCI-DSS-6.2.4", "violates")
        self._add_edge("CWE-89", "SOC2-CC7.1", "violates")
        self._add_edge("CWE-798", "PCI-DSS-3.2", "violates")
        self._add_edge("CWE-79", "PCI-DSS-6.2.4", "violates")

        # CWE -> Mitigation mapping
        self._add_edge("CWE-89", "M-PARAM", "mitigated_by")
        self._add_edge("CWE-78", "M-PARAM", "mitigated_by")
        self._add_edge("CWE-798", "M-ENV", "mitigated_by")
        self._add_edge("CWE-22", "M-SAN", "mitigated_by")

    def get_related_entities(self, entity_id: str, relation_type: Optional[str] = None) -> List[Dict]:
        """Finds all related nodes connected to the source entity.

        Args:
            entity_id: The starting node ID (e.g. ``"CWE-89"``).
            relation_type: Optional edge relation filtering string (e.g. ``"violates"``).

        Returns:
            List of related node dictionaries containing their ID, type, and attributes.
        """
        targets = []
        source_edges = self.edges.get(entity_id, {})
        
        for target_id, rel in source_edges.items():
            if relation_type and rel != relation_type:
                continue
                
            # Locate node metadata from dictionary types
            for node_type, type_nodes in self.nodes.items():
                if target_id in type_nodes:
                    targets.append({
                        "id": target_id,
                        "type": node_type,
                        "relation": rel,
                        "attributes": type_nodes[target_id]
                    })
                    
        return targets

    def find_all_violations(self, cwe_id: str) -> List[str]:
        """Convenience method to query compliance violations for a given CWE.

        Args:
            cwe_id: The target CWE identifier.

        Returns:
            List of violation names.
        """
        related = self.get_related_entities(cwe_id, "violates")
        return [node["attributes"]["name"] for node in related]
