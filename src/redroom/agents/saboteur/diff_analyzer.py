"""Git diff analyzer for code changes."""

import re
from typing import Dict, List, Tuple
import structlog

logger = structlog.get_logger()


class DiffAnalyzer:
    """Analyzes git diffs to extract relevant code changes."""
    
    def __init__(self):
        """Initialize diff analyzer."""
        logger.info("diff_analyzer_initialized")
    
    def parse_diff(self, diff_text: str) -> Dict[str, List[str]]:
        """
        Parse git diff into structured format.
        
        Args:
            diff_text: Raw git diff text
            
        Returns:
            Dictionary with added, removed, and modified lines
        """
        changes = {
            "added": [],
            "removed": [],
            "modified_files": [],
            "context": []
        }
        
        current_file = None
        
        for line in diff_text.split('\n'):
            # Track file being modified
            if line.startswith('+++'):
                current_file = line[6:].strip()
                if current_file != '/dev/null':
                    changes["modified_files"].append(current_file)
            
            # Added lines
            elif line.startswith('+') and not line.startswith('+++'):
                changes["added"].append(line[1:].strip())
            
            # Removed lines
            elif line.startswith('-') and not line.startswith('---'):
                changes["removed"].append(line[1:].strip())
            
            # Context lines
            elif line.startswith(' '):
                changes["context"].append(line[1:].strip())
        
        logger.info(
            "diff_parsed",
            added=len(changes["added"]),
            removed=len(changes["removed"]),
            files=len(changes["modified_files"])
        )
        
        return changes
    
    def extract_functions(self, code: str, language: str = "python") -> List[Dict[str, str]]:
        """
        Extract function definitions from code.
        
        Args:
            code: Source code
            language: Programming language
            
        Returns:
            List of function definitions
        """
        functions = []
        
        if language == "python":
            # Match Python function definitions
            pattern = r'^\s*(async\s+)?def\s+(\w+)\s*\((.*?)\):'
            for match in re.finditer(pattern, code, re.MULTILINE):
                functions.append({
                    "name": match.group(2),
                    "params": match.group(3),
                    "is_async": bool(match.group(1)),
                    "line": code[:match.start()].count('\n') + 1
                })
        
        elif language == "javascript":
            # Match JavaScript function definitions
            patterns = [
                r'function\s+(\w+)\s*\((.*?)\)',
                r'const\s+(\w+)\s*=\s*\((.*?)\)\s*=>',
                r'(\w+)\s*:\s*function\s*\((.*?)\)'
            ]
            for pattern in patterns:
                for match in re.finditer(pattern, code):
                    functions.append({
                        "name": match.group(1),
                        "params": match.group(2),
                        "line": code[:match.start()].count('\n') + 1
                    })
        
        logger.info("functions_extracted", count=len(functions), language=language)
        return functions
    
    def identify_security_patterns(self, changes: Dict[str, List[str]]) -> List[str]:
        """
        Identify potential security-related patterns in changes.
        
        Args:
            changes: Parsed diff changes
            
        Returns:
            List of identified patterns
        """
        patterns = []
        added_code = ' '.join(changes["added"])
        context_code = ' '.join(changes["context"])
        all_code = added_code + ' ' + context_code  # Include context for better detection
        
        # Race condition indicators
        if any(keyword in all_code for keyword in ['asyncio.sleep', 'time.sleep', 'setTimeout']):
            if any(keyword in all_code for keyword in ['balance', 'account', 'transaction', 'transfer', 'deduct', 'credit']):
                patterns.append("potential_race_condition")
        
        # SQL injection indicators
        if 'execute(' in added_code and any(op in added_code for op in ['%', '+', 'f"', "f'"]):
            patterns.append("potential_sql_injection")
        
        # Authentication bypass indicators
        if any(keyword in added_code for keyword in ['if user', 'if admin', 'if role']):
            if '==' in added_code or 'is' in added_code:
                patterns.append("potential_auth_bypass")
        
        # Hardcoded secrets
        if any(keyword in added_code for keyword in ['password', 'secret', 'api_key', 'token']):
            if '=' in added_code:
                patterns.append("potential_hardcoded_secret")
        
        # Command injection
        if any(keyword in added_code for keyword in ['subprocess', 'os.system', 'exec', 'eval']):
            patterns.append("potential_command_injection")
        
        # Path traversal
        if 'open(' in added_code or 'read' in added_code:
            if '..' in added_code or 'user_input' in added_code:
                patterns.append("potential_path_traversal")
        
        logger.info("security_patterns_identified", patterns=patterns)
        return patterns
    
    def calculate_risk_score(self, changes: Dict[str, List[str]], patterns: List[str]) -> float:
        """
        Calculate risk score for changes.
        
        Args:
            changes: Parsed diff changes
            patterns: Identified security patterns
            
        Returns:
            Risk score (0.0 to 1.0)
        """
        score = 0.0
        
        # Base score on number of patterns
        score += len(patterns) * 0.2
        
        # Increase score for critical files
        critical_files = ['auth', 'login', 'payment', 'transaction', 'admin']
        for file in changes["modified_files"]:
            if any(keyword in file.lower() for keyword in critical_files):
                score += 0.15
        
        # Increase score for large changes
        total_changes = len(changes["added"]) + len(changes["removed"])
        if total_changes > 50:
            score += 0.1
        
        # Cap at 1.0
        return min(score, 1.0)
    
    def get_context_window(
        self,
        diff_text: str,
        target_line: int,
        window_size: int = 5
    ) -> str:
        """
        Get context window around a specific line.
        
        Args:
            diff_text: Full diff text
            target_line: Target line number
            window_size: Number of lines before/after
            
        Returns:
            Context window text
        """
        lines = diff_text.split('\n')
        start = max(0, target_line - window_size)
        end = min(len(lines), target_line + window_size + 1)
        
        return '\n'.join(lines[start:end])
