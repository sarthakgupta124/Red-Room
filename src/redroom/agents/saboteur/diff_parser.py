"""Git diff parser for The Red Room Saboteur agent."""

import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import structlog

logger = structlog.get_logger()


@dataclass
class DiffChange:
    """Represents a change in a Git diff."""
    file_path: str
    change_type: str  # 'added', 'modified', 'deleted'
    added_lines: List[str]
    removed_lines: List[str]
    context_lines: List[str]
    line_numbers: Dict[str, int]  # {'start': int, 'end': int}
    
    def get_functions(self) -> List[str]:
        """Extract function names from changes."""
        functions = []
        patterns = [
            r'def\s+(\w+)\s*\(',  # Python
            r'function\s+(\w+)\s*\(',  # JavaScript
            r'async\s+function\s+(\w+)\s*\(',  # Async JS
            r'(\w+)\s*=\s*\([^)]*\)\s*=>', # Arrow functions
            r'(public|private|protected)\s+\w+\s+(\w+)\s*\(',  # Java/C#
        ]
        
        all_lines = self.added_lines + self.removed_lines
        for line in all_lines:
            for pattern in patterns:
                matches = re.findall(pattern, line)
                if matches:
                    if isinstance(matches[0], tuple):
                        functions.extend([m for m in matches[0] if m and not m in ['public', 'private', 'protected']])
                    else:
                        functions.extend(matches)
        
        return list(set(functions))
    
    def get_api_endpoints(self) -> List[str]:
        """Extract API endpoint patterns from changes."""
        endpoints = []
        patterns = [
            r'@app\.route\(["\']([^"\']+)["\']',  # Flask
            r'@router\.(get|post|put|delete)\(["\']([^"\']+)["\']',  # FastAPI
            r'app\.(get|post|put|delete)\(["\']([^"\']+)["\']',  # Express
            r'Route\(["\']([^"\']+)["\']',  # ASP.NET
        ]
        
        all_lines = self.added_lines + self.removed_lines
        for line in all_lines:
            for pattern in patterns:
                matches = re.findall(pattern, line)
                if matches:
                    for match in matches:
                        if isinstance(match, tuple):
                            endpoints.append(match[-1])  # Get the path
                        else:
                            endpoints.append(match)
        
        return list(set(endpoints))


class DiffParser:
    """Parses Git diffs to extract security-relevant changes."""
    
    def __init__(self):
        """Initialize diff parser."""
        logger.info("diff_parser_initialized")
    
    def parse(self, diff_text: str) -> List[DiffChange]:
        """
        Parse Git diff text into structured changes.
        
        Args:
            diff_text: Raw Git diff output
            
        Returns:
            List of DiffChange objects
        """
        logger.info("parsing_diff", size=len(diff_text))
        
        changes = []
        current_file = None
        current_added = []
        current_removed = []
        current_context = []
        line_start = 0
        
        lines = diff_text.split('\n')
        
        for i, line in enumerate(lines):
            # New file marker
            if line.startswith('diff --git'):
                # Save previous file if exists
                if current_file:
                    changes.append(DiffChange(
                        file_path=current_file,
                        change_type=self._determine_change_type(current_added, current_removed),
                        added_lines=current_added.copy(),
                        removed_lines=current_removed.copy(),
                        context_lines=current_context.copy(),
                        line_numbers={'start': line_start, 'end': i}
                    ))
                
                # Extract file path
                match = re.search(r'b/(.+)$', line)
                if match:
                    current_file = match.group(1)
                    current_added = []
                    current_removed = []
                    current_context = []
                    line_start = i
            
            # Added line
            elif line.startswith('+') and not line.startswith('+++'):
                current_added.append(line[1:].strip())
            
            # Removed line
            elif line.startswith('-') and not line.startswith('---'):
                current_removed.append(line[1:].strip())
            
            # Context line
            elif line.startswith(' '):
                current_context.append(line[1:].strip())
        
        # Save last file
        if current_file:
            changes.append(DiffChange(
                file_path=current_file,
                change_type=self._determine_change_type(current_added, current_removed),
                added_lines=current_added,
                removed_lines=current_removed,
                context_lines=current_context,
                line_numbers={'start': line_start, 'end': len(lines)}
            ))
        
        logger.info("diff_parsed", files=len(changes))
        return changes
    
    def _determine_change_type(self, added: List[str], removed: List[str]) -> str:
        """Determine type of change."""
        if added and not removed:
            return 'added'
        elif removed and not added:
            return 'deleted'
        else:
            return 'modified'
    
    def extract_security_context(self, changes: List[DiffChange]) -> Dict[str, Any]:
        """
        Extract security-relevant context from changes.
        
        Args:
            changes: List of DiffChange objects
            
        Returns:
            Security context dictionary
        """
        context = {
            'files_changed': [],
            'functions_modified': [],
            'api_endpoints': [],
            'security_keywords': [],
            'change_summary': {
                'added': 0,
                'modified': 0,
                'deleted': 0
            }
        }
        
        security_keywords = [
            'auth', 'password', 'token', 'secret', 'api_key',
            'session', 'cookie', 'jwt', 'oauth', 'permission',
            'admin', 'user', 'role', 'access', 'validate',
            'sanitize', 'escape', 'sql', 'query', 'execute'
        ]
        
        for change in changes:
            context['files_changed'].append({
                'path': change.file_path,
                'type': change.change_type
            })
            
            # Count changes
            context['change_summary'][change.change_type] += 1
            
            # Extract functions
            functions = change.get_functions()
            context['functions_modified'].extend(functions)
            
            # Extract API endpoints
            endpoints = change.get_api_endpoints()
            context['api_endpoints'].extend(endpoints)
            
            # Check for security keywords
            all_text = ' '.join(change.added_lines + change.removed_lines).lower()
            for keyword in security_keywords:
                if keyword in all_text and keyword not in context['security_keywords']:
                    context['security_keywords'].append(keyword)
        
        # Deduplicate
        context['functions_modified'] = list(set(context['functions_modified']))
        context['api_endpoints'] = list(set(context['api_endpoints']))
        
        logger.info("security_context_extracted",
                   files=len(context['files_changed']),
                   functions=len(context['functions_modified']),
                   endpoints=len(context['api_endpoints']),
                   keywords=len(context['security_keywords']))
        
        return context
    
    def is_security_relevant(self, changes: List[DiffChange]) -> bool:
        """
        Determine if changes are security-relevant.
        
        Args:
            changes: List of DiffChange objects
            
        Returns:
            True if security-relevant, False otherwise
        """
        context = self.extract_security_context(changes)
        
        # Security-relevant if:
        # 1. Contains security keywords
        # 2. Modifies API endpoints
        # 3. Changes authentication/authorization code
        
        is_relevant = (
            len(context['security_keywords']) > 0 or
            len(context['api_endpoints']) > 0 or
            any('auth' in f['path'].lower() or 'security' in f['path'].lower() 
                for f in context['files_changed'])
        )
        
        logger.info("security_relevance_check", is_relevant=is_relevant)
        return is_relevant
