"""AST validation for generated code."""

import ast
from typing import List, Dict, Any
import structlog

logger = structlog.get_logger()


class ASTValidator:
    """Validates Python code using AST parsing."""
    
    def __init__(self):
        """Initialize AST validator."""
        logger.info("ast_validator_initialized")
    
    def validate_syntax(self, code: str) -> bool:
        """
        Validate Python code syntax.
        
        Args:
            code: Python source code
            
        Returns:
            True if valid, False otherwise
        """
        try:
            ast.parse(code)
            logger.info("syntax_valid")
            return True
        except SyntaxError as e:
            logger.error("syntax_invalid", error=str(e), line=e.lineno)
            return False
    
    def check_dangerous_patterns(self, code: str) -> List[Dict[str, Any]]:
        """
        Check for dangerous code patterns.
        
        Args:
            code: Python source code
            
        Returns:
            List of detected dangerous patterns
        """
        dangerous_patterns = []
        
        try:
            tree = ast.parse(code)
            
            for node in ast.walk(tree):
                # Check for eval/exec
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        if node.func.id in ['eval', 'exec', 'compile']:
                            dangerous_patterns.append({
                                "type": "dangerous_function",
                                "function": node.func.id,
                                "line": node.lineno,
                                "severity": "critical"
                            })
                
                # Check for os.system
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Attribute):
                        if node.func.attr == 'system':
                            dangerous_patterns.append({
                                "type": "system_call",
                                "line": node.lineno,
                                "severity": "high"
                            })
                
                # Check for file operations
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        if node.func.id in ['open', '__import__']:
                            dangerous_patterns.append({
                                "type": "file_operation",
                                "function": node.func.id,
                                "line": node.lineno,
                                "severity": "medium"
                            })
        
        except SyntaxError:
            pass
        
        logger.info("dangerous_patterns_checked", count=len(dangerous_patterns))
        return dangerous_patterns
    
    def extract_imports(self, code: str) -> List[str]:
        """Extract all imports from code."""
        imports = []
        
        try:
            tree = ast.parse(code)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.append(node.module)
        
        except SyntaxError:
            pass
        
        return imports
    
    def validate_allowed_imports(
        self,
        code: str,
        allowed_modules: List[str]
    ) -> bool:
        """
        Validate that code only uses allowed imports.
        
        Args:
            code: Python source code
            allowed_modules: List of allowed module names
            
        Returns:
            True if all imports are allowed
        """
        imports = self.extract_imports(code)
        
        for imp in imports:
            base_module = imp.split('.')[0]
            if base_module not in allowed_modules:
                logger.warning("disallowed_import", module=imp)
                return False
        
        return True
