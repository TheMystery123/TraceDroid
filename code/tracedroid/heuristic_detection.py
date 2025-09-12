import os
import re
from typing import List, Dict, Any, Generator

# --- 1. Rule Abstract Base Class (The Rule Interface) ---
class Rule:
    """
    Abstract base class for all scanning rules.
    Each subclass represents a specific issue to be checked.
    """
    @property
    def name(self) -> str:
        """Unique name/ID for the rule."""
        # Return class name as default name
        return self.__class__.__name__
    
    @property
    def issue_type(self) -> str:
        """Type of issue detected by this rule (for reporting)."""
        raise NotImplementedError

    @property
    def suggestion(self) -> str:
        """Fix suggestion for the discovered issue."""
        raise NotImplementedError

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        """
        Analyze a single file to find issues.
        If issues are found, this method should yield a dictionary containing issue information.
        
        Args:
            file_path (str): Path of the file being analyzed.
            lines (List[str]): List of all line contents of the file.

        Yields:
            Generator[Dict[str, Any], None, None]: Dictionary describing the issue.
        """
        raise NotImplementedError



class UnsafeStartActivityRule(Rule):
    """
    Detects startActivity calls that may throw ActivityNotFoundException but are not wrapped in try-catch blocks.
    This rule specifically targets Intent.ACTION_VIEW calls which are most likely to fail when no browser is available.
    """
    issue_type = "Unsafe startActivity Call Without Exception Handling"
    suggestion = "The startActivity() call can throw an ActivityNotFoundException if no app can handle the Intent (e.g., no browser for ACTION_VIEW). Wrap it in a try-catch block with ActivityNotFoundException handling."
    
    # Match startActivity(...) or startActivityForResult(...)
    START_ACTIVITY_PATTERN = re.compile(r"(startActivity|startActivityForResult)\s*\(")
    
    # Pattern to detect Intent.ACTION_VIEW specifically (higher risk)
    ACTION_VIEW_PATTERN = re.compile(r"Intent\.ACTION_VIEW")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        try_block_stack = []
        catch_activity_not_found = False
        
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped_line = line.strip()

            if not stripped_line or stripped_line.startswith("//"):
                continue

            # Track try-catch blocks and specifically look for ActivityNotFoundException handling
            if "try " in stripped_line or stripped_line.startswith("try {") or stripped_line.endswith(" try"):
                try_block_stack.append(line_num)
                catch_activity_not_found = False  # Reset for new try block
            
            # Check for catch blocks with ActivityNotFoundException
            if "catch" in stripped_line and "ActivityNotFoundException" in stripped_line:
                catch_activity_not_found = True
            
            if stripped_line.startswith("}"):
                if try_block_stack:
                    try_block_stack.pop()
                    # If we're exiting a try block, reset the catch flag
                    if not try_block_stack:
                        catch_activity_not_found = False
            
            # Check for startActivity calls
            if self.START_ACTIVITY_PATTERN.search(line):
                # Check if this is a high-risk ACTION_VIEW call
                is_action_view = bool(self.ACTION_VIEW_PATTERN.search(line))
                
                # Issue severity depends on whether we're in a try block and have proper exception handling
                if not try_block_stack:
                    # No try-catch at all - high severity
                    severity = "HIGH" if is_action_view else "MEDIUM"
                    yield {
                        "line_num": line_num,
                        "code": line.strip(),
                        "detail": f"Unsafe {severity} risk call found: `{self.START_ACTIVITY_PATTERN.search(line).group().strip()}`. No exception handling detected.",
                        "severity": severity
                    }
                elif try_block_stack and not catch_activity_not_found:
                    # In try block but no ActivityNotFoundException handling - medium severity
                    severity = "MEDIUM" if is_action_view else "LOW"
                    yield {
                        "line_num": line_num,
                        "code": line.strip(),
                        "detail": f"Unsafe {severity} risk call found: `{self.START_ACTIVITY_PATTERN.search(line).group().strip()}`. Try block exists but no ActivityNotFoundException handling detected.",
                        "severity": severity
                    }


class StrictPeertubeChannelIdParsingRule(Rule):
    """
    Detects PeerTube channel link handler implementations that fail to handle leading slashes
    and short prefixes (a/, c/), and do not use an URL-scoped ID regex, leading to parsing errors.

    Mirrors the fix:
    - Use ID_URL_PATTERN with a leading '/' scope
    - fixId cleans leading '/'
    - Expand 'a/' to 'accounts/', 'c/' to 'video-channels/'
    """
    issue_type = "PeerTube channel ID parsing too permissive/incorrect"
    suggestion = "Use '/((accounts|a)|(video-channels|c))/([^/?&#]*)' and normalize IDs by removing leading '/' and expanding 'a/'/'c/'."

    BAD_ID_PATTERN_PATTERN = re.compile(r"ID_PATTERN\s*=\s*\"\(\(accounts\|a\)\|\(video-channels\|c\)\)/\(\[^/\?&#\]\*\)\"|ID_PATTERN\s*=")
    MISSING_URL_SCOPED_PATTERN = re.compile(r"ID_URL_PATTERN")
    FIXID_SIGNATURE_PATTERN = re.compile(r"fixId\s*\(\s*(@Nonnull\s*)?final\s*String\s+id\s*\)")
    CLEAN_LEADING_SLASH_PATTERN = re.compile(r"startsWith\s*\(\s*\"/\"\s*\)\s*\?\s*id\.substring\(1\)\s*:\s*id|cleanedId\s*=\s*id\.startsWith\(\"/\"\)\s*\?\s*id\.substring\(1\)\s*:\s*id")
    EXPAND_PREFIX_A_PATTERN = re.compile(r"startsWith\s*\(\s*\"a/\"\s*\).*accounts")
    EXPAND_PREFIX_C_PATTERN = re.compile(r"startsWith\s*\(\s*\"c/\"\s*\).*video-channels")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        # Target Java files in extractor/services/peertube
        if not file_path.endswith('.java'):
            return
        if 'peertube' not in file_path.lower():
            return

        content = "\n".join(lines)

        has_id_url_pattern = bool(self.MISSING_URL_SCOPED_PATTERN.search(content))
        has_fixid_signature = bool(self.FIXID_SIGNATURE_PATTERN.search(content))
        has_clean_leading = bool(self.CLEAN_LEADING_SLASH_PATTERN.search(content))
        has_expand_a = bool(self.EXPAND_PREFIX_A_PATTERN.search(content))
        has_expand_c = bool(self.EXPAND_PREFIX_C_PATTERN.search(content))

        # If ID_URL_PATTERN is missing or normalization missing, flag
        if not has_id_url_pattern or not (has_fixid_signature and has_clean_leading and has_expand_a and has_expand_c):
            line_num = 1
            detail_bits = []
            if not has_id_url_pattern:
                detail_bits.append("Define ID_URL_PATTERN='/((accounts|a)|(video-channels|c))/([^/?&#]*)'")
            if not has_clean_leading:
                detail_bits.append("Remove leading '/' in fixId")
            if not has_expand_a:
                detail_bits.append("Expand 'a/' -> 'accounts/' in fixId")
            if not has_expand_c:
                detail_bits.append("Expand 'c/' -> 'video-channels/' in fixId")

            yield {
                "line_num": line_num,
                "code": "PeerTube link handler patterns",
                "detail": "; ".join(detail_bits) or "PeerTube channel ID parsing likely incomplete.",
                "severity": "MEDIUM",
            }

class UnsafeBrowserIntentRule(Rule):
    """
    Detects unsafe browser intent calls that can cause ActivityNotFoundException.
    This rule specifically targets the exact pattern shown in the PR:
    startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(...)))
    """
    issue_type = "Unsafe Browser Intent Without Exception Handling"
    suggestion = "Browser intent calls can fail if no browser app is installed. Wrap startActivity in try-catch with ActivityNotFoundException handling and show user-friendly error message."
    
    # Pattern to match the exact browser intent pattern from the PR
    BROWSER_INTENT_PATTERN = re.compile(r"startActivity\s*\(\s*new\s+Intent\s*\(\s*Intent\.ACTION_VIEW\s*,\s*Uri\.parse\s*\(")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        try_block_stack = []
        catch_activity_not_found = False
        in_try_block = False
        
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped_line = line.strip()

            if not stripped_line or stripped_line.startswith("//"):
                continue

            # Track try-catch blocks with more precise detection
            if "try" in stripped_line and ("{" in stripped_line or stripped_line.endswith("try")):
                try_block_stack.append(line_num)
                in_try_block = True
                catch_activity_not_found = False
            
            # Check for catch blocks with ActivityNotFoundException
            if "catch" in stripped_line and "ActivityNotFoundException" in stripped_line:
                catch_activity_not_found = True
            
            # Track closing braces
            if stripped_line == "}" and try_block_stack:
                try_block_stack.pop()
                if not try_block_stack:
                    in_try_block = False
                    catch_activity_not_found = False
            
            # Check for the specific browser intent pattern
            if self.BROWSER_INTENT_PATTERN.search(line):
                if not in_try_block:
                    yield {
                        "line_num": line_num,
                        "code": line.strip(),
                        "detail": "Browser intent call without any exception handling. This will crash if no browser app is installed.",
                        "severity": "HIGH"
                    }
                elif in_try_block and not catch_activity_not_found:
                    yield {
                        "line_num": line_num,
                        "code": line.strip(),
                        "detail": "Browser intent call in try block but no ActivityNotFoundException handling. Generic exception handling may not provide user-friendly error message.",
                        "severity": "MEDIUM"
                                            }


class StrictFragmentBindingRule(Rule):
    """
    Strict rule to detect unsafe binding access in Fragment lifecycle callbacks.
    This rule specifically targets the exact pattern shown in the PR where
    binding-dependent methods are called without null checks in risky contexts.
    """
    issue_type = "Unsafe Fragment Binding Access in Lifecycle Callback"
    suggestion = "Binding-dependent methods should only be called when binding is not null. Add `&& _binding != null` to the condition or wrap the call in a null check block."
    
    # Pattern to match the exact pattern from the PR: method calls without null checks
    METHOD_CALL_PATTERN = re.compile(r"([a-zA-Z_][a-zA-Z0-9_]*)\s*\(\s*\)")
    
    # Risky lifecycle contexts where binding might be null
    RISKY_CONTEXTS = [
        'onEvents', 'onStart', 'onResume', 'onPause', 'onStop', 
        'onDestroyView', 'onDetach', 'onDestroy', 'onViewStateRestored',
        'onCreateView', 'onViewCreated'
    ]

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        # Only analyze Kotlin files
        if not file_path.endswith('.kt'):
            return
            
        # 1. Check if this is a Fragment class
        is_fragment = False
        binding_var_name = None
        
        for line in lines:
            if "class " in line and "Fragment(" in line:
                is_fragment = True
            # Look for binding declaration
            binding_match = re.search(r"private\s+var\s+(_?binding)\s*:\s*\w+Binding\?\s*=\s*null", line)
            if binding_match:
                binding_var_name = binding_match.group(1)
                break
        
        if not is_fragment or not binding_var_name:
            return
        
        # 2. Find binding-dependent methods
        binding_methods = self._find_binding_dependent_methods(lines, binding_var_name)
        
        # 3. Scan for unsafe calls in risky contexts
        for issue in self._scan_risky_contexts(lines, binding_var_name, binding_methods):
            yield issue
    
    def _find_binding_dependent_methods(self, lines: List[str], binding_var_name: str) -> set:
        """Find methods that directly access the binding variable."""
        dependent_methods = set()
        
        # Pattern to match method calls that access binding
        binding_access_pattern = re.compile(rf"\b{re.escape(binding_var_name)}\.[a-zA-Z_][a-zA-Z0-9_]*\s*\(")
        
        for line in lines:
            matches = binding_access_pattern.findall(line)
            for match in matches:
                # Extract method name from the match
                method_name = match.split('.')[-1].split('(')[0]
                dependent_methods.add(method_name)
        
        return dependent_methods
    
    def _scan_risky_contexts(self, lines: List[str], binding_var_name: str, binding_methods: set) -> Generator[Dict[str, Any], None, None]:
        """Scan for unsafe calls in risky lifecycle contexts."""
        current_method = None
        in_risky_context = False
        in_safe_block = False
        safe_block_indent = -1
        
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped_line = line.strip()
            
            if not stripped_line or stripped_line.startswith("//"):
                continue
            
            # Track current method
            if "fun " in stripped_line and "(" in stripped_line:
                method_match = re.search(r"fun\s+([a-zA-Z_][a-zA-Z0-9_]*)", stripped_line)
                if method_match:
                    current_method = method_match.group(1)
                    in_risky_context = any(context in current_method for context in self.RISKY_CONTEXTS)
            
            # Track safe blocks (if statements with null checks)
            if f"if" in stripped_line and f"{binding_var_name} != null" in stripped_line:
                in_safe_block = True
                safe_block_indent = len(line) - len(line.lstrip(' '))
                continue
            
            # Exit safe block when indentation decreases or closing brace
            current_indent = len(line) - len(line.lstrip(' '))
            if in_safe_block and (stripped_line == "}" or current_indent < safe_block_indent):
                in_safe_block = False
                safe_block_indent = -1
            
            # Check for calls to binding-dependent methods
            for method_name in binding_methods:
                method_call_pattern = re.compile(rf"\b{re.escape(method_name)}\s*\(\s*\)")
                if method_call_pattern.search(line):
                    # Check if this is an unsafe call in risky context
                    if in_risky_context and not in_safe_block:
                        yield {
                            "line_num": line_num,
                            "code": line.strip(),
                            "detail": f"Unsafe call to binding-dependent method '{method_name}' in risky lifecycle context '{current_method}' without null check for '{binding_var_name}'. This can cause NullPointerException if the Fragment's view is destroyed.",
                            "severity": "HIGH"
                        }


class UnsafeArrayIndexAccessRule(Rule):
    """
    Detects unsafe array index access that can cause IndexOutOfBoundsException.
    This rule specifically targets the pattern shown in the PR where array indices
    are used without bounds checking.
    """
    issue_type = "Unsafe Array Index Access Without Bounds Check"
    suggestion = "Array indices should be validated against array bounds before use to prevent IndexOutOfBoundsException. Add bounds checking or use safe access methods."
    
    # Pattern to match array access with variables as indices
    ARRAY_ACCESS_PATTERN = re.compile(r"(\w+)\s*\[\s*(\w+)\s*\]")
    # Pattern to match string/char sequence access
    STRING_ACCESS_PATTERN = re.compile(r"(\w+)\.(charAt|substring|setSpan)\s*\(\s*(\w+)\s*")
    
    # Methods that commonly use indices without bounds checking
    RISKY_METHODS = ['charAt', 'substring', 'setSpan', 'get', 'set']

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped_line = line.strip()
            
            if not stripped_line or stripped_line.startswith("//"):
                continue
            
            # Check for array access patterns
            array_match = self.ARRAY_ACCESS_PATTERN.search(line)
            if array_match:
                array_name = array_match.group(1)
                index_var = array_match.group(2)
                
                # Check if bounds checking exists
                if not self._has_bounds_check(lines, i, array_name, index_var):
                    yield {
                        "line_num": line_num,
                        "code": line.strip(),
                        "detail": f"Unsafe array access: `{array_name}[{index_var}]` without bounds checking. This can cause IndexOutOfBoundsException.",
                        "severity": "HIGH"
                    }
            
            # Check for string/sequence access patterns
            string_match = self.STRING_ACCESS_PATTERN.search(line)
            if string_match:
                string_name = string_match.group(1)
                method_name = string_match.group(2)
                index_var = string_match.group(3)
                
                # Check if bounds checking exists
                if not self._has_bounds_check(lines, i, string_name, index_var):
                    yield {
                        "line_num": line_num,
                        "code": line.strip(),
                        "detail": f"Unsafe {method_name} access: `{string_name}.{method_name}({index_var})` without bounds checking. This can cause IndexOutOfBoundsException.",
                        "severity": "HIGH"
                    }
    
    def _has_bounds_check(self, lines: List[str], current_line: int, container_name: str, index_var: str) -> bool:
        """Check if there's a bounds check for the given container and index."""
        # Look for bounds checking in the current method
        method_start = self._find_method_start(lines, current_line)
        method_end = self._find_method_end(lines, current_line)
        
        if method_start == -1 or method_end == -1:
            return False
        
        # Check for bounds checking patterns
        bounds_patterns = [
            rf"{index_var}\s*<\s*{container_name}\.length",
            rf"{index_var}\s*<=\s*{container_name}\.length",
            rf"{index_var}\s*>=?\s*0\s*&&\s*{index_var}\s*<",
            rf"{container_name}\.length\s*>\s*{index_var}",
            rf"isInsideTextRange",  # Specific pattern from the PR
        ]
        
        for line_num in range(method_start, method_end + 1):
            line = lines[line_num]
            for pattern in bounds_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    return True
        
        return False
    
    def _find_method_start(self, lines: List[str], current_line: int) -> int:
        """Find the start of the current method."""
        for i in range(current_line, -1, -1):
            if "public " in lines[i] or "private " in lines[i] or "protected " in lines[i]:
                if "(" in lines[i] and ")" in lines[i]:
                    return i
        return -1
    
    def _find_method_end(self, lines: List[str], current_line: int) -> int:
        """Find the end of the current method."""
        brace_count = 0
        in_method = False
        
        for i in range(current_line, len(lines)):
            line = lines[i]
            if "{" in line:
                brace_count += line.count("{")
                in_method = True
            if "}" in line:
                brace_count -= line.count("}")
                if in_method and brace_count == 0:
                    return i
        return -1


class UnsafeNullComparisonRule(Rule):
    """
    Detects unsafe null comparisons in comparator functions that can cause NullPointerException.
    This rule specifically targets the pattern shown in the PR where comparator methods
    directly access potentially null objects without null checks.
    """
    issue_type = "Unsafe Null Comparison in Comparator"
    suggestion = "Comparator methods should handle null values explicitly to prevent NullPointerException. Add null checks or use null-safe comparison methods."
    
    # Pattern to match comparator methods and lambda expressions
    COMPARATOR_PATTERN = re.compile(r"(Collections\.sort|\.sort|Comparator|compare)\s*\(.*\)")
    # Pattern to match method calls that might return null
    NULLABLE_METHOD_PATTERN = re.compile(r"(\w+)\.(\w+)\s*\(\s*\)")
    
    # Methods that commonly return null
    NULLABLE_METHODS = ['updatedAt', 'getDate', 'getTime', 'getValue', 'getData']

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        in_comparator = False
        comparator_start = -1
        
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped_line = line.strip()
            
            if not stripped_line or stripped_line.startswith("//"):
                continue
            
            # Check for comparator context
            if self.COMPARATOR_PATTERN.search(line):
                in_comparator = True
                comparator_start = i
                continue
            
            # Check for method calls that might return null
            if in_comparator:
                method_match = self.NULLABLE_METHOD_PATTERN.search(line)
                if method_match:
                    object_name = method_match.group(1)
                    method_name = method_match.group(2)
                    
                    # Check if this is a potentially nullable method
                    if method_name in self.NULLABLE_METHODS:
                        # Check if there's null handling in the comparator
                        if not self._has_null_handling(lines, comparator_start, i):
                            yield {
                                "line_num": line_num,
                                "code": line.strip(),
                                "detail": f"Unsafe null comparison: `{object_name}.{method_name}()` in comparator without null handling. This can cause NullPointerException.",
                                "severity": "HIGH"
                            }
                
                # Check if we've exited the comparator context
                if "}" in line and self._is_comparator_end(lines, i):
                    in_comparator = False
                    comparator_start = -1
    
    def _has_null_handling(self, lines: List[str], start_line: int, current_line: int) -> bool:
        """Check if there's null handling in the comparator."""
        null_patterns = [
            r"==\s*null",
            r"!=\s*null",
            r"null\s*==",
            r"null\s*!=",
            r"Objects\.isNull",
            r"Objects\.nonNull"
        ]
        
        for line_num in range(start_line, current_line + 1):
            line = lines[line_num]
            for pattern in null_patterns:
                if re.search(pattern, line):
                    return True
        
        return False
    
    def _is_comparator_end(self, lines: List[str], current_line: int) -> int:
        """Check if this line ends a comparator context."""
        # Simple heuristic: if we see a closing brace and we're in a comparator context
        return "}" in lines[current_line]


class UnsafeParcelableIntentRule(Rule):
    """
    Detects unsafe Parcelable object passing in Intents that can cause TransactionTooLargeException.
    This rule specifically targets the pattern shown in the PR where large objects are passed
    directly as Parcelable extras without compression.
    """
    issue_type = "Unsafe Parcelable Intent Extra Without Compression"
    suggestion = "Large Parcelable objects should be compressed before passing as Intent extras to prevent TransactionTooLargeException. Use compression utilities or pass only essential data."
    
    # Pattern to match Intent.putExtra with Parcelable objects
    PARCELABLE_EXTRA_PATTERN = re.compile(r"\.putExtra\s*\(\s*\"[^\"]+\"\s*,\s*(\w+)\s*\)")
    
    # Common large Parcelable types that should be compressed
    LARGE_PARCELABLE_TYPES = ['Release', 'Repository', 'User', 'Issue', 'PullRequest', 'Commit']

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped_line = line.strip()
            
            if not stripped_line or stripped_line.startswith("//"):
                continue
            
            # Check for putExtra calls with Parcelable objects
            extra_match = self.PARCELABLE_EXTRA_PATTERN.search(line)
            if extra_match:
                object_name = extra_match.group(1)
                
                # Check if this is a potentially large Parcelable type
                if self._is_large_parcelable_type(lines, object_name):
                    # Check if compression is used
                    if not self._has_compression(lines, i, object_name):
                        yield {
                            "line_num": line_num,
                            "code": line.strip(),
                            "detail": f"Unsafe Parcelable extra: `{object_name}` passed without compression. This can cause TransactionTooLargeException for large objects.",
                            "severity": "MEDIUM"
                        }
    
    def _is_large_parcelable_type(self, lines: List[str], object_name: str) -> bool:
        """Check if the object is a potentially large Parcelable type."""
        # Look for variable declarations or type information
        for line in lines:
            # Check for variable declarations
            decl_pattern = rf"{object_name}\s+(\w+)\s*="
            decl_match = re.search(decl_pattern, line)
            if decl_match:
                var_name = decl_match.group(1)
                # Check if the type is in our list of large Parcelable types
                for large_type in self.LARGE_PARCELABLE_TYPES:
                    if large_type in line:
                        return True
        
        # Check if the object name itself suggests a large type
        for large_type in self.LARGE_PARCELABLE_TYPES:
            if large_type.lower() in object_name.lower():
                return True
        
        return False
    
    def _has_compression(self, lines: List[str], current_line: int, object_name: str) -> bool:
        """Check if compression is used for the Parcelable object."""
        compression_patterns = [
            rf"putCompressedParcelableExtra.*{object_name}",
            rf"IntentUtils\.putCompressedParcelableExtra",
            rf"compress.*{object_name}",
            rf"serialize.*{object_name}"
        ]
        
        # Check current line and a few lines before
        for line_num in range(max(0, current_line - 5), current_line + 1):
            line = lines[line_num]
            for pattern in compression_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    return True
        
        return False


class StrictRxSubscribeErrorHandlerRule(Rule):
    """
    Detects RxJava subscribe() usages without an onError handler.

    Matches cases like `.subscribe()` or `.subscribe { ... }` or single-argument subscribe
    without providing an error consumer, which leads to OnErrorNotImplementedException.
    """
    issue_type = "Rx subscribe() without onError handler"
    suggestion = "Always provide an onError handler to subscribe(), e.g., subscribe(onNext, onError)."

    SUBSCRIBE_CALL_PATTERN = re.compile(r"\.subscribe\s*(\(|\{)")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        if not (file_path.endswith('.kt') or file_path.endswith('.java')):
            return

        i = 0
        while i < len(lines):
            line = lines[i]
            s = line.strip()
            if not s or s.startswith("//"):
                i += 1
                continue

            m = self.SUBSCRIBE_CALL_PATTERN.search(s)
            if not m:
                i += 1
                continue

            # Capture the subscribe call content until the closing paren/brace at same depth
            opener = m.group(1)
            closer = ')' if opener == '(' else '}'
            depth = 0
            buf_parts = []
            j = i
            found = False
            while j < len(lines):
                part = lines[j]
                buf_parts.append(part.strip())
                for ch in part:
                    if ch == opener:
                        depth += 1
                        found = True
                    elif ch == closer and found:
                        depth -= 1
                        if depth == 0:
                            break
                if depth == 0 and found:
                    break
                j += 1

            subscribe_args_text = " ".join(buf_parts)
            # Heuristic: if there's no comma separating multiple args and no explicit onError mention
            # and not using Consumer with error, then flag.
            has_on_error_hint = ('onError' in subscribe_args_text) or ('Consumer' in subscribe_args_text and 'error' in subscribe_args_text)
            has_multiple_args = ',' in subscribe_args_text

            if not has_multiple_args and not has_on_error_hint:
                yield {
                    "line_num": i + 1,
                    "code": s,
                    "detail": "subscribe() is used without an explicit onError handler; this can cause OnErrorNotImplementedException.",
                    "severity": "HIGH",
                }

            i = j + 1 if j >= i else i + 1


class StrictRxIoThreadingForWritesRule(Rule):
    """
    Detects RxJava chains that perform database writes from UI thread due to missing observeOn(Schedulers.io()).

    Heuristic based on the PR: ensure an explicit observeOn(Schedulers.io()) before doOnNext/subscribe
    where side-effects call repository write methods or Realm.executeTransaction.
    """
    issue_type = "Rx chain missing observeOn(Schedulers.io()) before writes"
    suggestion = "Insert observeOn(Schedulers.io()) before performing blocking DB writes in Rx callbacks."

    OBSERVE_ON_IO_PATTERN = re.compile(r"\.observeOn\s*\(\s*Schedulers\.io\s*\(\s*\)\s*\)")
    SUBSCRIBE_ON_IO_PATTERN = re.compile(r"\.subscribeOn\s*\(\s*Schedulers\.io\s*\(\s*\)\s*\)")
    SIDE_EFFECT_WRITE_HINT_PATTERN = re.compile(r"(executeTransaction|blockNumber\s*\(|unblockNumber\s*\(|insert\s*\(|update\s*\(|delete\s*\()")
    SUBSCRIBE_PATTERN = re.compile(r"\.subscribe\s*(\(|\{)")
    DO_ON_NEXT_PATTERN = re.compile(r"\.doOnNext\s*\(")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        if not (file_path.endswith('.kt') or file_path.endswith('.java')):
            return

        for i, raw in enumerate(lines):
            s = raw.strip()
            if not s or s.startswith("//"):
                continue

            if self.SUBSCRIBE_PATTERN.search(s) or self.DO_ON_NEXT_PATTERN.search(s):
                # Look back a window for observeOn/io and subscribeOn/io and side-effect hints
                window_start = max(0, i - 12)
                window_text = "\n".join(x.strip() for x in lines[window_start:i+1])

                has_observe_on_io = bool(self.OBSERVE_ON_IO_PATTERN.search(window_text))
                has_subscribe_on_io = bool(self.SUBSCRIBE_ON_IO_PATTERN.search(window_text))
                has_write_hint = bool(self.SIDE_EFFECT_WRITE_HINT_PATTERN.search(window_text))

                if has_write_hint and not has_observe_on_io:
                    # Even if subscribeOn(IO) is present, without observeOn(IO) the downstream may still be on main
                    yield {
                        "line_num": i + 1,
                        "code": s,
                        "detail": "DB write side-effect in Rx chain without observeOn(Schedulers.io()); may execute on UI thread.",
                        "severity": "HIGH",
                    }

# ... rest of the code ...
class UnsafeNullableObjectAccessRule(Rule):
    """
    Detects unsafe method calls on potentially null objects that can cause NullPointerException.
    This rule specifically targets the pattern shown in the PR where method calls are made
    on objects without null checks.
    """
    issue_type = "Unsafe Nullable Object Method Call"
    suggestion = "Method call on a potentially null object without a null check. Add `if (object != null)` or use safe call operator (`?.`) to prevent NullPointerException."
    
    # Pattern to match method calls on variables
    METHOD_CALL_PATTERN = re.compile(r"(\w+(?:\.\w+)*)\.(\w+)\s*\(")
    
    # Pattern to match null checks
    NULL_CHECK_PATTERN = re.compile(r"if\s*\(\s*(\w+(?:\.\w+)*)\s*!=\s*null\s*\)")
    
    # Pattern to match safe call operators (Kotlin)
    SAFE_CALL_PATTERN = re.compile(r"(\w+(?:\.\w+)*)\?\.(\w+)\s*\(")
    
    # Common nullable object patterns (parameters, fields, etc.)
    NULLABLE_CONTEXTS = ['player', 'view', 'binding', 'context', 'activity', 'fragment']

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped_line = line.strip()
            
            if not stripped_line or stripped_line.startswith("//"):
                continue
            
            # Check for method calls on variables
            method_match = self.METHOD_CALL_PATTERN.search(line)
            if method_match:
                object_name = method_match.group(1)
                method_name = method_match.group(2)
                
                # Skip if this is a safe call (Kotlin ?. operator)
                if self.SAFE_CALL_PATTERN.search(line):
                    continue
                
                # Check if this object is likely to be nullable
                if self._is_likely_nullable(lines, object_name):
                    # Check if there's a null check before this call
                    if not self._has_null_check(lines, i, object_name):
                        yield {
                            "line_num": line_num,
                            "code": line.strip(),
                            "detail": f"Unsafe method call: `{object_name}.{method_name}()` called without null check. This can cause NullPointerException if {object_name} is null.",
                            "severity": "HIGH"
                        }
    
    def _is_likely_nullable(self, lines: List[str], object_name: str) -> bool:
        """Check if the object is likely to be nullable based on context and naming."""
        # Check if object name suggests nullable context
        for nullable_context in self.NULLABLE_CONTEXTS:
            if nullable_context.lower() in object_name.lower():
                return True
        
        # Check for nullable declarations in the file
        nullable_patterns = [
            rf"{re.escape(object_name)}\s*\?[^=]*=",  # Kotlin nullable type
            rf"{re.escape(object_name)}\s*=\s*null",  # Explicit null assignment
            rf"@Nullable.*{re.escape(object_name)}",   # Java @Nullable annotation
            rf"Optional<.*{re.escape(object_name)}",   # Java Optional
        ]
        
        for line in lines:
            for pattern in nullable_patterns:
                if re.search(pattern, line):
                    return True
        
        return False
    
    def _has_null_check(self, lines: List[str], current_line: int, object_name: str) -> bool:
        """Check if there's a null check for the given object before the current line."""
        # Look for null checks in the current method
        method_start = self._find_method_start(lines, current_line)
        method_end = self._find_method_end(lines, current_line)
        
        if method_start == -1 or method_end == -1:
            return False
        
        # Check for null check patterns before the current line
        null_check_patterns = [
            rf"if\s*\(\s*{re.escape(object_name)}\s*!=\s*null\s*\)",
            rf"if\s*\(\s*null\s*!=\s*{re.escape(object_name)}\s*\)",
            rf"if\s*\(\s*{re.escape(object_name)}\s*!=\s*null\s*&&",
            rf"if\s*\(\s*{re.escape(object_name)}\s*&&\s*{re.escape(object_name)}\s*!=\s*null",
            rf"Objects\.requireNonNull\s*\(\s*{re.escape(object_name)}",
            rf"assert\s+{re.escape(object_name)}\s*!=\s*null",
        ]
        
        # Check if the method call is in an if statement with null check
        current_line_content = lines[current_line]
        if "if" in current_line_content:
            # Look for the if condition pattern with null check
            for pattern in null_check_patterns:
                if re.search(pattern, current_line_content):
                    return True
        
        # Check previous lines in the same method for null checks
        for line_num in range(method_start, current_line + 1):
            line = lines[line_num]
            for pattern in null_check_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Check if this null check is in a condition that would prevent the unsafe call
                    if self._is_protective_null_check(line, object_name):
                        return True
        
        return False
    
    def _is_protective_null_check(self, line: str, object_name: str) -> bool:
        """Check if the null check is protective (would prevent the unsafe call)."""
        # Check for positive null checks that would prevent unsafe calls
        positive_patterns = [
            rf"if\s*\(\s*{re.escape(object_name)}\s*!=\s*null",  # if (object != null)
            rf"if\s*\(\s*null\s*!=\s*{re.escape(object_name)}",  # if (null != object)
            rf"Objects\.requireNonNull\s*\(\s*{re.escape(object_name)}",  # Objects.requireNonNull(object)
        ]
        
        for pattern in positive_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                return True
        
        return False
    
    def _find_method_start(self, lines: List[str], current_line: int) -> int:
        """Find the start of the current method."""
        for i in range(current_line, -1, -1):
            if "public " in lines[i] or "private " in lines[i] or "protected " in lines[i]:
                if "(" in lines[i] and ")" in lines[i]:
                    return i
        return -1
    
    def _find_method_end(self, lines: List[str], current_line: int) -> int:
        """Find the end of the current method."""
        brace_count = 0
        in_method = False
        
        for i in range(current_line, len(lines)):
            line = lines[i]
            if "{" in line:
                brace_count += line.count("{")
                in_method = True
            if "}" in line:
                brace_count -= line.count("}")
                if in_method and brace_count == 0:
                    return i
        return -1


class UnsafeServiceLifecycleAccessRule(Rule):
    """
    Detects unsafe object access in Android Service lifecycle methods that can cause crashes.
    This rule specifically targets the pattern shown in the PR where Service methods access
    objects without null checks, which can cause crashes on Android 8+ when the service
    is not properly managed.
    """
    issue_type = "Unsafe Service Lifecycle Object Access"
    suggestion = "Service lifecycle methods should check if objects are null before accessing them. This prevents crashes on Android 8+ when the service is not properly managed. Add null checks or ensure proper initialization."
    
    # Pattern to match Service lifecycle methods
    SERVICE_LIFECYCLE_PATTERN = re.compile(r"(onCreate|onStartCommand|onDestroy|onTaskRemoved|onBind|onUnbind)")
    
    # Pattern to match method calls on potentially null objects
    UNSAFE_ACCESS_PATTERN = re.compile(r"(\w+)\.(\w+)\s*\(")
    
    # Pattern to match null checks
    NULL_CHECK_PATTERN = re.compile(r"if\s*\(\s*(\w+)\s*!=\s*null\s*\)")
    
    # Common Service-related objects that should be null-checked
    SERVICE_OBJECTS = ['player', 'notification', 'mediaSession', 'exoPlayer', 'playQueue']

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        # Only analyze Java files (Android Services are typically in Java)
        if not file_path.endswith('.java'):
            return
            
        current_method = None
        in_service_lifecycle = False
        
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped_line = line.strip()
            
            if not stripped_line or stripped_line.startswith("//"):
                continue
            
            # Check if we're in a Service lifecycle method
            if "public " in stripped_line and "(" in stripped_line:
                lifecycle_match = self.SERVICE_LIFECYCLE_PATTERN.search(stripped_line)
                if lifecycle_match:
                    current_method = lifecycle_match.group(1)
                    in_service_lifecycle = True
                    continue
            
            # Check for method calls on potentially null objects in Service lifecycle methods
            if in_service_lifecycle:
                access_match = self.UNSAFE_ACCESS_PATTERN.search(line)
                if access_match:
                    object_name = access_match.group(1)
                    method_name = access_match.group(2)
                    
                    # Check if this is a Service-related object that should be null-checked
                    if self._is_service_object(lines, object_name):
                        # Check if there's a null check before this access
                        if not self._has_null_check_in_method(lines, i, object_name, current_method):
                            yield {
                                "line_num": line_num,
                                "code": line.strip(),
                                "detail": f"Unsafe object access in Service lifecycle method '{current_method}': `{object_name}.{method_name}()` called without null check. This can cause crashes on Android 8+.",
                                "severity": "HIGH"
                            }
                
                # Check if we've exited the Service lifecycle method
                if "}" in line and self._is_method_end(lines, i):
                    in_service_lifecycle = False
                    current_method = None
    
    def _is_service_object(self, lines: List[str], object_name: str) -> bool:
        """Check if the object is a Service-related object that should be null-checked."""
        # Check if object name suggests Service context
        for service_object in self.SERVICE_OBJECTS:
            if service_object.lower() in object_name.lower():
                return True
        
        # Check for Service-related field declarations
        service_patterns = [
            rf"private\s+\w+\s+{re.escape(object_name)}",  # private field
            rf"protected\s+\w+\s+{re.escape(object_name)}",  # protected field
            rf"public\s+\w+\s+{re.escape(object_name)}",  # public field
            rf"{re.escape(object_name)}\s*=\s*new",  # object instantiation
        ]
        
        for line in lines:
            for pattern in service_patterns:
                if re.search(pattern, line):
                    return True
        
        return False
    
    def _has_null_check_in_method(self, lines: List[str], current_line: int, object_name: str, method_name: str) -> bool:
        """Check if there's a null check for the given object in the current method."""
        # Find the method boundaries
        method_start = self._find_service_method_start(lines, current_line, method_name)
        method_end = self._find_service_method_end(lines, current_line)
        
        if method_start == -1 or method_end == -1:
            return False
        
        # Check for null check patterns in the method
        null_check_patterns = [
            rf"if\s*\(\s*{re.escape(object_name)}\s*!=\s*null\s*\)",
            rf"if\s*\(\s*null\s*!=\s*{re.escape(object_name)}\s*\)",
            rf"if\s*\(\s*{re.escape(object_name)}\s*!=\s*null\s*&&",
            rf"if\s*\(\s*{re.escape(object_name)}\s*&&\s*{re.escape(object_name)}\s*!=\s*null",
            rf"Objects\.requireNonNull\s*\(\s*{re.escape(object_name)}",
        ]
        
        # Check if the method call is in an if statement with null check
        current_line_content = lines[current_line]
        if "if" in current_line_content:
            for pattern in null_check_patterns:
                if re.search(pattern, current_line_content):
                    return True
        
        # Check previous lines in the same method for null checks
        for line_num in range(method_start, current_line + 1):
            line = lines[line_num]
            for pattern in null_check_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    if self._is_protective_null_check(line, object_name):
                        return True
        
        return False
    
    def _is_protective_null_check(self, line: str, object_name: str) -> bool:
        """Check if the null check is protective (would prevent the unsafe call)."""
        positive_patterns = [
            rf"if\s*\(\s*{re.escape(object_name)}\s*!=\s*null",  # if (object != null)
            rf"if\s*\(\s*null\s*!=\s*{re.escape(object_name)}",  # if (null != object)
            rf"Objects\.requireNonNull\s*\(\s*{re.escape(object_name)}",  # Objects.requireNonNull(object)
        ]
        
        for pattern in positive_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                return True
        
        return False
    
    def _find_service_method_start(self, lines: List[str], current_line: int, method_name: str) -> int:
        """Find the start of the current Service method."""
        for i in range(current_line, -1, -1):
            if f"public " in lines[i] and f"{method_name}(" in lines[i]:
                return i
        return -1
    
    def _find_service_method_end(self, lines: List[str], current_line: int) -> int:
        """Find the end of the current Service method."""
        brace_count = 0
        in_method = False
        
        for i in range(current_line, len(lines)):
            line = lines[i]
            if "{" in line:
                brace_count += line.count("{")
                in_method = True
            if "}" in line:
                brace_count -= line.count("}")
                if in_method and brace_count == 0:
                    return i
        return -1
    
    def _is_method_end(self, lines: List[str], current_line: int) -> bool:
        """Check if this line ends a method."""
        return "}" in lines[current_line]


class UnsafeSystemServiceCallRule(Rule):
    """
    Detects unsafe Android system service calls that can throw IllegalStateException.
    This rule specifically targets the pattern shown in the PR where system service
    methods are called without proper exception handling.
    """
    issue_type = "Unsafe System Service Call Without Exception Handling"
    suggestion = "Android system service calls can throw IllegalStateException in certain states. Wrap system service calls in try-catch blocks to handle potential exceptions gracefully."
    
    # Pattern to match Android system service calls
    SYSTEM_SERVICE_PATTERN = re.compile(r"(\w+)\.(\w+)\s*\(")
    
    # Common Android system services that can throw IllegalStateException
    SYSTEM_SERVICES = [
        'launcherApps', 'userManager', 'activityManager', 'packageManager',
        'windowManager', 'inputMethodManager', 'notificationManager',
        'locationManager', 'telephonyManager', 'connectivityManager'
    ]
    
    # Methods that commonly throw IllegalStateException
    RISKY_METHODS = [
        'getShortcuts', 'getInstalledPackages', 'getRunningTasks',
        'getRecentTasks', 'getAppTasks', 'getRunningServices',
        'getSystemService', 'queryIntentActivities', 'queryIntentServices'
    ]

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        # Only analyze Kotlin/Java files
        if not (file_path.endswith('.kt') or file_path.endswith('.java')):
            return
            
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped_line = line.strip()
            
            if not stripped_line or stripped_line.startswith("//"):
                continue
            
            # Check for system service method calls
            service_match = self.SYSTEM_SERVICE_PATTERN.search(line)
            if service_match:
                service_name = service_match.group(1)
                method_name = service_match.group(2)
                
                # Check if this is a system service call that might throw IllegalStateException
                if self._is_system_service_call(service_name, method_name):
                    # Check if there's exception handling
                    if not self._has_exception_handling(lines, i, service_name, method_name):
                        yield {
                            "line_num": line_num,
                            "code": line.strip(),
                            "detail": f"Unsafe system service call: `{service_name}.{method_name}()` without exception handling. This can throw IllegalStateException in certain Android states.",
                            "severity": "MEDIUM"
                        }
    
    def _is_system_service_call(self, service_name: str, method_name: str) -> bool:
        """Check if this is a system service call that might throw IllegalStateException."""
        # Check if service name suggests system service
        is_system_service = any(service.lower() in service_name.lower() for service in self.SYSTEM_SERVICES)
        
        # Check if method name suggests risky operation
        is_risky_method = any(method.lower() in method_name.lower() for method in self.RISKY_METHODS)
        
        return is_system_service and is_risky_method
    
    def _has_exception_handling(self, lines: List[str], current_line: int, service_name: str, method_name: str) -> bool:
        """Check if there's exception handling for the system service call."""
        # Look for try-catch blocks around the current line
        method_start = self._find_method_start(lines, current_line)
        method_end = self._find_method_end(lines, current_line)
        
        if method_start == -1 or method_end == -1:
            return False
        
        # Check for try-catch patterns
        try_catch_patterns = [
            r"try\s*\{",
            r"catch\s*\(\s*IllegalStateException",
            r"catch\s*\(\s*Exception",
            r"catch\s*\(\s*.*Exception",
        ]
        
        in_try_block = False
        has_catch = False
        
        for line_num in range(method_start, method_end + 1):
            line = lines[line_num]
            
            # Check for try block start
            if re.search(r"try\s*\{", line):
                in_try_block = True
                has_catch = False
                continue
            
            # Check for catch block
            if in_try_block and re.search(r"catch\s*\(\s*.*Exception", line):
                has_catch = True
                continue
            
            # Check for try block end
            if in_try_block and "}" in line:
                # If we're in a try block and have a catch, check if our service call is in this try block
                if has_catch and self._is_in_try_block(lines, current_line, line_num):
                    return True
                in_try_block = False
                has_catch = False
        
        return False
    
    def _is_in_try_block(self, lines: List[str], service_call_line: int, try_end_line: int) -> bool:
        """Check if the service call is within the try block."""
        # Simple heuristic: check if the service call line is between try start and try end
        try_start = -1
        
        for i in range(service_call_line, -1, -1):
            if re.search(r"try\s*\{", lines[i]):
                try_start = i
                break
        
        if try_start == -1:
            return False
        
        # Check if service call is between try start and try end
        return try_start < service_call_line < try_end_line
    
    def _find_method_start(self, lines: List[str], current_line: int) -> int:
        """Find the start of the current method."""
        for i in range(current_line, -1, -1):
            if "fun " in lines[i] or "public " in lines[i] or "private " in lines[i] or "protected " in lines[i]:
                if "(" in lines[i] and ")" in lines[i]:
                    return i
        return -1
    
    def _find_method_end(self, lines: List[str], current_line: int) -> int:
        """Find the end of the current method."""
        brace_count = 0
        in_method = False
        
        for i in range(current_line, len(lines)):
            line = lines[i]
            if "{" in line:
                brace_count += line.count("{")
                in_method = True
            if "}" in line:
                brace_count -= line.count("}")
                if in_method and brace_count == 0:
                    return i
        return -1


class UnsafeFileSystemOperationRule(Rule):
    """
    Detects unsafe file system operations that can throw ReadException without proper fallback handling.
    This rule specifically targets the pattern shown in the PR where file system operations
    are called without proper exception handling and fallback mechanisms.
    """
    issue_type = "Unsafe File System Operation Without Exception Handling"
    suggestion = "File system operations can throw ReadException in certain states. Wrap file operations in try-catch blocks with proper fallback mechanisms to handle potential exceptions gracefully."
    
    # Pattern to match file system operations
    FILE_OPERATION_PATTERN = re.compile(r"(\w+)\.(\w+)\s*\(")
    
    # Common file system operations that can throw ReadException
    FILE_OPERATIONS = [
        'lookup', 'lookupFiles', 'exists', 'canRead', 'canWrite',
        'walk', 'listFiles', 'getFiles', 'getDirectories',
        'read', 'write', 'delete', 'create', 'mkdir'
    ]
    
    # File system related objects
    FILE_OBJECTS = [
        'gatewaySwitch', 'path', 'file', 'directory', 'folder',
        'localPath', 'safPath', 'apath', 'lookup', 'lookupFiles'
    ]
    
    # Methods that should have fallback handling
    FALLBACK_METHODS = [
        'lookup', 'lookupFiles', 'exists', 'walk'
    ]

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        # Only analyze Kotlin/Java files
        if not (file_path.endswith('.kt') or file_path.endswith('.java')):
            return
            
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped_line = line.strip()
            
            if not stripped_line or stripped_line.startswith("//"):
                continue
            
            # Check for file system operations
            operation_match = self.FILE_OPERATION_PATTERN.search(line)
            if operation_match:
                object_name = operation_match.group(1)
                method_name = operation_match.group(2)
                
                # Check if this is a file system operation that might throw ReadException
                if self._is_file_system_operation(object_name, method_name):
                    # Check if there's proper exception handling with fallback
                    if not self._has_proper_exception_handling(lines, i, object_name, method_name):
                        yield {
                            "line_num": line_num,
                            "code": line.strip(),
                            "detail": f"Unsafe file system operation: `{object_name}.{method_name}()` without proper exception handling. This can throw ReadException and should have fallback mechanisms.",
                            "severity": "HIGH"
                        }
    
    def _is_file_system_operation(self, object_name: str, method_name: str) -> bool:
        """Check if this is a file system operation that might throw ReadException."""
        # Check if object name suggests file system context
        is_file_object = any(obj.lower() in object_name.lower() for obj in self.FILE_OBJECTS)
        
        # Check if method name suggests file operation
        is_file_operation = any(op.lower() in method_name.lower() for op in self.FILE_OPERATIONS)
        
        return is_file_object and is_file_operation
    
    def _has_proper_exception_handling(self, lines: List[str], current_line: int, object_name: str, method_name: str) -> bool:
        """Check if there's proper exception handling with fallback for the file operation."""
        # Look for try-catch blocks around the current line
        method_start = self._find_method_start(lines, current_line)
        method_end = self._find_method_end(lines, current_line)
        
        if method_start == -1 or method_end == -1:
            return False
        
        # Check for try-catch patterns with fallback
        in_try_block = False
        has_catch = False
        has_fallback = False
        
        for line_num in range(method_start, method_end + 1):
            line = lines[line_num]
            
            # Check for try block start
            if re.search(r"try\s*\{", line):
                in_try_block = True
                has_catch = False
                has_fallback = False
                continue
            
            # Check for catch block
            if in_try_block and re.search(r"catch\s*\(\s*.*Exception", line):
                has_catch = True
                continue
            
            # Check for fallback mechanisms in catch block
            if in_try_block and has_catch:
                # Look for fallback patterns
                fallback_patterns = [
                    r"return\s+null",
                    r"return\s+empty",
                    r"return\s+\{\}",
                    r"return\s+emptySet",
                    r"return\s+emptyList",
                    r"throw\s+IOException",
                    r"throw\s+UnsupportedOperationException",
                    r"toAlternative",
                    r"toTargetType",
                    r"fallback"
                ]
                
                for pattern in fallback_patterns:
                    if re.search(pattern, line):
                        has_fallback = True
                        break
            
            # Check for try block end
            if in_try_block and "}" in line:
                # If we're in a try block and have a catch with fallback, check if our operation is in this try block
                if has_catch and has_fallback and self._is_in_try_block(lines, current_line, line_num):
                    return True
                in_try_block = False
                has_catch = False
                has_fallback = False
        
        return False
    
    def _is_in_try_block(self, lines: List[str], operation_line: int, try_end_line: int) -> bool:
        """Check if the file operation is within the try block."""
        # Simple heuristic: check if the operation line is between try start and try end
        try_start = -1
        
        for i in range(operation_line, -1, -1):
            if re.search(r"try\s*\{", lines[i]):
                try_start = i
                break
        
        if try_start == -1:
            return False
        
        # Check if operation is between try start and try end
        return try_start < operation_line < try_end_line
    
    def _find_method_start(self, lines: List[str], current_line: int) -> int:
        """Find the start of the current method."""
        for i in range(current_line, -1, -1):
            if "fun " in lines[i] or "public " in lines[i] or "private " in lines[i] or "protected " in lines[i]:
                if "(" in lines[i] and ")" in lines[i]:
                    return i
        return -1
    
    def _find_method_end(self, lines: List[str], current_line: int) -> int:
        """Find the end of the current method."""
        brace_count = 0
        in_method = False
        
        for i in range(current_line, len(lines)):
            line = lines[i]
            if "{" in line:
                brace_count += line.count("{")
                in_method = True
            if "}" in line:
                brace_count -= line.count("}")
                if in_method and brace_count == 0:
                    return i
        return -1
class UnsafeMathematicalFunctionRule(Rule):
    """
    Detects unsafe mathematical function implementations that lack proper boundary checks.
    This rule specifically targets the pattern shown in the PR where mathematical functions
    don't handle special values like negative numbers, zero, infinity, or NaN properly.
    """
    issue_type = "Unsafe Mathematical Function Without Boundary Checks"
    suggestion = "Mathematical functions should include proper boundary checks for special values like negative numbers, zero, infinity, and NaN. Add appropriate checks to prevent undefined behavior or incorrect results."
    
    # Pattern to match mathematical function definitions
    MATH_FUNCTION_PATTERN = re.compile(r"(fun|public|private|protected)\s+(\w+)\s*\([^)]*\)\s*:\s*(Double|Float|BigInteger|BigDecimal|Int|Long)")
    
    # Mathematical function names that should have boundary checks
    MATH_FUNCTIONS = [
        'factorial', 'sqrt', 'log', 'ln', 'exp', 'pow', 'sin', 'cos', 'tan',
        'asin', 'acos', 'atan', 'sinh', 'cosh', 'tanh', 'gamma', 'abs',
        'floor', 'ceil', 'round', 'truncate', 'mod', 'gcd', 'lcm'
    ]
    
    # Special values that should be checked
    SPECIAL_VALUES = [
        'Double.NaN', 'Float.NaN', 'NaN',
        'Double.POSITIVE_INFINITY', 'Float.POSITIVE_INFINITY', 'POSITIVE_INFINITY',
        'Double.NEGATIVE_INFINITY', 'Float.NEGATIVE_INFINITY', 'NEGATIVE_INFINITY',
        'Infinity', '-Infinity'
    ]
    
    # Boundary check patterns
    BOUNDARY_CHECK_PATTERNS = [
        r"if\s*\(\s*\w+\s*<=\s*0\s*\)",
        r"if\s*\(\s*\w+\s*==\s*0\s*\)",
        r"if\s*\(\s*\w+\s*<=\s*0\.0\s*\)",
        r"if\s*\(\s*\w+\s*==\s*0\.0\s*\)",
        r"if\s*\(\s*\w+\.isNaN\s*\(\s*\)\s*\)",
        r"if\s*\(\s*\w+\.isInfinite\s*\(\s*\)\s*\)",
        r"if\s*\(\s*\w+\s*>=\s*\d+\s*\)",
        r"if\s*\(\s*\w+\s*<=\s*\d+\s*\)"
    ]

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        # Only analyze Kotlin/Java files
        if not (file_path.endswith('.kt') or file_path.endswith('.java')):
            return
            
        current_function = None
        function_start = -1
        function_end = -1
        
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped_line = line.strip()
            
            if not stripped_line or stripped_line.startswith("//"):
                continue
            
            # Check for mathematical function definition
            function_match = self.MATH_FUNCTION_PATTERN.search(line)
            if function_match:
                function_name = function_match.group(2)
                
                # Check if this is a mathematical function that should have boundary checks
                if self._is_mathematical_function(function_name):
                    current_function = function_name
                    function_start = i
                    function_end = self._find_function_end(lines, i)
                    
                    # Check if the function has proper boundary checks
                    if not self._has_boundary_checks(lines, function_start, function_end):
                        yield {
                            "line_num": line_num,
                            "code": line.strip(),
                            "detail": f"Mathematical function '{function_name}' lacks proper boundary checks for special values (negative numbers, zero, infinity, NaN). This can lead to undefined behavior or incorrect results.",
                            "severity": "MEDIUM"
                        }
                    
                    current_function = None
                    function_start = -1
                    function_end = -1
    
    def _is_mathematical_function(self, function_name: str) -> bool:
        """Check if this is a mathematical function that should have boundary checks."""
        return any(math_func.lower() in function_name.lower() for math_func in self.MATH_FUNCTIONS)
    
    def _has_boundary_checks(self, lines: List[str], function_start: int, function_end: int) -> bool:
        """Check if the mathematical function has proper boundary checks."""
        if function_start == -1 or function_end == -1:
            return False
        
        has_boundary_check = False
        has_special_value_check = False
        
        for i in range(function_start, function_end + 1):
            line = lines[i]
            
            # Check for boundary conditions
            for pattern in self.BOUNDARY_CHECK_PATTERNS:
                if re.search(pattern, line):
                    has_boundary_check = True
                    break
            
            # Check for special value handling
            for special_value in self.SPECIAL_VALUES:
                if special_value in line:
                    has_special_value_check = True
                    break
            
            # Check for return statements with special values
            if re.search(r"return\s+(Double|Float)\.(NaN|POSITIVE_INFINITY|NEGATIVE_INFINITY)", line):
                has_special_value_check = True
            
            # Check for early returns that might indicate boundary handling
            if re.search(r"return\s+\w+", line) and i < function_end - 5:  # Early return
                has_boundary_check = True
        
        return has_boundary_check or has_special_value_check
    
    def _find_function_end(self, lines: List[str], function_start: int) -> int:
        """Find the end of the function."""
        brace_count = 0
        in_function = False
        
        for i in range(function_start, len(lines)):
            line = lines[i]
            if "{" in line:
                brace_count += line.count("{")
                in_function = True
            if "}" in line:
                brace_count -= line.count("}")
                if in_function and brace_count == 0:
                    return i
        return -1


class UnsafeAndroidPermissionRule(Rule):
    """
    Detects unsafe Android permission usage patterns that can cause runtime issues.
    This rule specifically targets the pattern shown in the PR where permissions
    are declared in AndroidManifest.xml but not properly handled at runtime.
    """
    issue_type = "Unsafe Android Permission Usage"
    suggestion = "Android permissions, especially runtime permissions, should be properly requested and handled. Ensure permission checks are implemented for Android 6+ and proper fallback mechanisms are in place."
    
    # Pattern to match permission declarations in AndroidManifest.xml
    PERMISSION_DECLARATION_PATTERN = re.compile(r'<uses-permission\s+android:name="([^"]+)"')
    
    # Pattern to match permission requests in code
    PERMISSION_REQUEST_PATTERN = re.compile(r'(requestPermissions?|checkSelfPermission|shouldShowRequestPermissionRationale)')
    
    # Pattern to match permission checks
    PERMISSION_CHECK_PATTERN = re.compile(r'(ContextCompat\.checkSelfPermission|ActivityCompat\.checkSelfPermission|checkSelfPermission)')
    
    # Runtime permissions that require explicit user consent (Android 6+)
    RUNTIME_PERMISSIONS = [
        'android.permission.CAMERA',
        'android.permission.RECORD_AUDIO',
        'android.permission.READ_EXTERNAL_STORAGE',
        'android.permission.WRITE_EXTERNAL_STORAGE',
        'android.permission.ACCESS_FINE_LOCATION',
        'android.permission.ACCESS_COARSE_LOCATION',
        'android.permission.READ_CONTACTS',
        'android.permission.WRITE_CONTACTS',
        'android.permission.READ_PHONE_STATE',
        'android.permission.CALL_PHONE',
        'android.permission.READ_CALL_LOG',
        'android.permission.WRITE_CALL_LOG',
        'android.permission.ADD_VOICEMAIL',
        'android.permission.USE_SIP',
        'android.permission.PROCESS_OUTGOING_CALLS',
        'android.permission.BODY_SENSORS',
        'android.permission.SEND_SMS',
        'android.permission.RECEIVE_SMS',
        'android.permission.READ_SMS',
        'android.permission.RECEIVE_WAP_PUSH',
        'android.permission.RECEIVE_MMS',
        'android.permission.POST_NOTIFICATIONS'
    ]
    
    # Dangerous permissions that require runtime handling
    DANGEROUS_PERMISSIONS = [
        'android.permission.SYSTEM_ALERT_WINDOW',
        'android.permission.WRITE_SETTINGS',
        'android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS'
    ]

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        # Only analyze AndroidManifest.xml and Kotlin/Java files
        if not (file_path.endswith('.xml') or file_path.endswith('.kt') or file_path.endswith('.java')):
            return
        
        # For AndroidManifest.xml, check for permission declarations
        if file_path.endswith('AndroidManifest.xml'):
            for i, line in enumerate(lines):
                line_num = i + 1
                stripped_line = line.strip()
                
                if not stripped_line or stripped_line.startswith("<!--"):
                    continue
                
                # Check for permission declarations
                permission_match = self.PERMISSION_DECLARATION_PATTERN.search(line)
                if permission_match:
                    permission_name = permission_match.group(1)
                    
                    # Check if this is a runtime permission that requires proper handling
                    if self._is_runtime_permission(permission_name):
                        yield {
                            "line_num": line_num,
                            "code": line.strip(),
                            "detail": f"Runtime permission '{permission_name}' declared in AndroidManifest.xml. Ensure proper runtime permission handling is implemented in the code.",
                            "severity": "MEDIUM"
                        }
        
        # For Kotlin/Java files, check for permission usage patterns
        else:
            has_permission_requests = False
            has_permission_checks = False
            
            for i, line in enumerate(lines):
                line_num = i + 1
                stripped_line = line.strip()
                
                if not stripped_line or stripped_line.startswith("//"):
                    continue
                
                # Check for permission request patterns
                if self.PERMISSION_REQUEST_PATTERN.search(line):
                    has_permission_requests = True
                
                # Check for permission check patterns
                if self.PERMISSION_CHECK_PATTERN.search(line):
                    has_permission_checks = True
                
                # Check for potential permission-related issues
                if self._has_potential_permission_issue(line):
                    yield {
                        "line_num": line_num,
                        "code": line.strip(),
                        "detail": "Potential permission-related code detected. Ensure proper permission handling and fallback mechanisms are implemented.",
                        "severity": "LOW"
                    }
    
    def _is_runtime_permission(self, permission_name: str) -> bool:
        """Check if the permission is a runtime permission that requires explicit handling."""
        return permission_name in self.RUNTIME_PERMISSIONS or permission_name in self.DANGEROUS_PERMISSIONS
    
    def _has_potential_permission_issue(self, line: str) -> bool:
        """Check for potential permission-related issues in code."""
        # Check for direct permission-dependent operations without proper checks
        permission_dependent_patterns = [
            r'\.getSystemService\s*\(\s*Context\.CAMERA_SERVICE\s*\)',
            r'\.getSystemService\s*\(\s*Context\.LOCATION_SERVICE\s*\)',
            r'\.getSystemService\s*\(\s*Context\.TELEPHONY_SERVICE\s*\)',
            r'MediaStore\.Images\.Media\.getBitmap',
            r'MediaStore\.Audio\.Media\.getContentUri',
            r'LocationManager\.requestLocationUpdates',
            r'Camera\.open',
            r'MediaRecorder',
            r'TelephonyManager\.getDeviceId',
            r'ContentResolver\.query\s*\(\s*ContactsContract\.Contacts\.CONTENT_URI'
        ]
        
        for pattern in permission_dependent_patterns:
            if re.search(pattern, line):
                return True
        
        return False


class UnsafeCollectionAccessRule(Rule):
    """
    Detects unsafe collection access that can cause NoSuchElementException.
    This rule specifically targets the pattern shown in the PR where collection
    methods like last(), first(), single() are called without checking if the
    collection is empty.
    """
    issue_type = "Unsafe Collection Access Without Empty Check"
    suggestion = "Collection methods like last(), first(), single() can throw NoSuchElementException if the collection is empty. Always check if the collection is not empty before calling these methods."
    
    # Pattern to match unsafe collection method calls
    UNSAFE_COLLECTION_PATTERN = re.compile(r"(\w+(?:\.\w+)*)\.(last|first|single|min|max)\s*\(\s*\)")
    
    # Methods that can throw NoSuchElementException on empty collections
    UNSAFE_METHODS = ['last', 'first', 'single', 'min', 'max']
    
    # Pattern to match empty checks
    EMPTY_CHECK_PATTERN = re.compile(r"!?\s*(\w+(?:\.\w+)*)\.(isEmpty|isNotEmpty|size\s*[=!]=\s*0)")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped_line = line.strip()
            
            if not stripped_line or stripped_line.startswith("//"):
                continue
            
            # Check for unsafe collection method calls
            collection_match = self.UNSAFE_COLLECTION_PATTERN.search(line)
            if collection_match:
                collection_name = collection_match.group(1)
                method_name = collection_match.group(2)
                
                # Check if this is a potentially unsafe method
                if method_name in self.UNSAFE_METHODS:
                    # Check if there's an empty check before this call
                    if not self._has_empty_check(lines, i, collection_name):
                        yield {
                            "line_num": line_num,
                            "code": line.strip(),
                            "detail": f"Unsafe collection access: `{collection_name}.{method_name}()` called without checking if the collection is empty. This can cause NoSuchElementException.",
                            "severity": "HIGH"
                        }
    
    def _has_empty_check(self, lines: List[str], current_line: int, collection_name: str) -> bool:
        """Check if there's an empty check for the given collection before the current line."""
        # Look for empty checks in the current method
        method_start = self._find_method_start(lines, current_line)
        method_end = self._find_method_end(lines, current_line)
        
        if method_start == -1 or method_end == -1:
            return False
        
        # Check for empty check patterns before the current line
        empty_check_patterns = [
            rf"!?\s*{re.escape(collection_name)}\.isEmpty\s*\(\s*\)",
            rf"!?\s*{re.escape(collection_name)}\.isNotEmpty\s*\(\s*\)",
            rf"{re.escape(collection_name)}\.size\s*[=!]=\s*0",
            rf"{re.escape(collection_name)}\.size\s*>\s*0",
            rf"{re.escape(collection_name)}\.count\s*\(\s*\)\s*[=!]=\s*0",
            rf"{re.escape(collection_name)}\.count\s*\(\s*\)\s*>\s*0"
        ]
        
        # Check if the unsafe call is in an if statement with empty check
        current_line_content = lines[current_line]
        if "if" in current_line_content:
            # Look for the if condition pattern
            if_condition_pattern = rf"if\s*\(\s*!?\s*{re.escape(collection_name)}\.(isEmpty|isNotEmpty|size\s*[=!]=\s*0)"
            if re.search(if_condition_pattern, current_line_content):
                return True
        
        # Check previous lines in the same method for empty checks
        for line_num in range(method_start, current_line + 1):
            line = lines[line_num]
            for pattern in empty_check_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Check if this empty check is in a condition that would prevent the unsafe call
                    if self._is_protective_check(line, collection_name):
                        return True
        
        return False
    
    def _is_protective_check(self, line: str, collection_name: str) -> bool:
        """Check if the empty check is protective (would prevent the unsafe call)."""
        # Check for positive empty checks that would prevent unsafe calls
        positive_patterns = [
            rf"!{re.escape(collection_name)}\.isEmpty",  # !collection.isEmpty()
            rf"{re.escape(collection_name)}\.isNotEmpty",  # collection.isNotEmpty()
            rf"{re.escape(collection_name)}\.size\s*>\s*0",  # collection.size > 0
            rf"{re.escape(collection_name)}\.count\s*\(\s*\)\s*>\s*0"  # collection.count() > 0
        ]
        
        for pattern in positive_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                return True
        
        return False
    
    def _find_method_start(self, lines: List[str], current_line: int) -> int:
        """Find the start of the current method."""
        for i in range(current_line, -1, -1):
            if "fun " in lines[i] and "(" in lines[i]:
                return i
        return -1
    
    def _find_method_end(self, lines: List[str], current_line: int) -> int:
        """Find the end of the current method."""
        brace_count = 0
        in_method = False
        
        for i in range(current_line, len(lines)):
            line = lines[i]
            if "{" in line:
                brace_count += line.count("{")
                in_method = True
            if "}" in line:
                brace_count -= line.count("}")
                if in_method and brace_count == 0:
                    return i
        return -1


class StrictLiveDataListTerminalOpRule(Rule):
    """
    Detects unsafe usage of LiveData<List<...>> where code calls value!!.last()/first()/single()
    (or on Kotlin Flow/State holders similarly) without guarding emptiness, which can throw
    NoSuchElementException when the list is empty.

    Mirrors the fix pattern from the PR: add an explicit isEmpty() check before calling last().
    """
    issue_type = "Unsafe LiveData<List> terminal op without empty check"
    suggestion = "Guard LiveData<List>.value with null and empty checks before calling last()/first()/single()."

    # Matches foo.value!!.last() / foo.value!!.first() / foo.value!!.single()
    LIVE_DATA_UNSAFE_PATTERN = re.compile(r"\bvalue!!\.(last|first|single)\s*\(\s*\)")

    # Also match common holder names: fileContents.value!!.last()
    HOLDER_UNSAFE_PATTERN = re.compile(r"\b(\w+)\.value!!\.(last|first|single)\s*\(\s*\)")

    # Nearby protective checks
    NULL_OR_EMPTY_CHECK_PATTERN = re.compile(r"(value\s*!=\s*null|!\s*\w+\.isEmpty\(\)|\w+\.isNotEmpty\(\)|size\s*>\s*0)")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        if not file_path.endswith('.kt'):
            return

        for i, raw in enumerate(lines):
            s = raw.strip()
            if not s or s.startswith("//"):
                continue

            if self.LIVE_DATA_UNSAFE_PATTERN.search(s) or self.HOLDER_UNSAFE_PATTERN.search(s):
                # Look back a small window for guards
                window_start = max(0, i - 8)
                window = "\n".join(x.strip() for x in lines[window_start:i+1])
                has_guard = bool(self.NULL_OR_EMPTY_CHECK_PATTERN.search(window))

                if not has_guard:
                    yield {
                        "line_num": i + 1,
                        "code": s,
                        "detail": "LiveData<List>.value!!.last()/first()/single() without null/empty guard can throw NoSuchElementException.",
                        "severity": "HIGH",
                    }


class StrictNonNullAssertionTerminalOpRule(Rule):
    """
    Detects risky chains using the non-null assertion operator (!!) immediately followed by
    terminal list operations like last()/first()/single() without guarding emptiness.
    """
    issue_type = "Risky !! with terminal list op without empty guard"
    suggestion = "Avoid using !! with last()/first()/single() unless you guard the list emptiness first. Prefer safe calls and checks."

    RISKY_CHAIN_PATTERN = re.compile(r"!!\.(last|first|single)\s*\(\s*\)")
    EMPTY_GUARD_PATTERN = re.compile(r"(isNotEmpty\(\)|!\s*\w+\.isEmpty\(\)|size\s*>\s*0)")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        if not (file_path.endswith('.kt') or file_path.endswith('.java')):
            return

        for i, raw in enumerate(lines):
            s = raw.strip()
            if not s or s.startswith("//"):
                continue

            if self.RISKY_CHAIN_PATTERN.search(s):
                window_start = max(0, i - 6)
                window = "\n".join(x.strip() for x in lines[window_start:i+1])
                has_guard = bool(self.EMPTY_GUARD_PATTERN.search(window))
                if not has_guard:
                    yield {
                        "line_num": i + 1,
                        "code": s,
                        "detail": "Non-null assertion (!!) followed by last()/first()/single() without empty guard can crash on empty lists.",
                        "severity": "HIGH",
                    }

class UnsafeFragmentBindingAccessRule(Rule):
    """
    Detects unsafe access to nullable View Binding properties in Fragments.
    
    During Fragment lifecycle, the binding object becomes null after view destruction.
    Direct access to binding in async callbacks may cause NullPointerException.
    This rule specifically targets the pattern shown in the PR where binding-dependent
    methods are called without null checks in lifecycle callbacks.
    """
    issue_type = "Unsafe Fragment View Binding Access Without Null Check"
    suggestion = "Fragment's View Binding can be null after onDestroyView(). Methods that depend on binding should only be called when binding is not null. Add `&& _binding != null` to the condition or use safe call operators (`?.`)."

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        # 1. Confirm this is a Fragment and find the nullable binding variable name
        is_fragment = False
        binding_var_name = None
        
        # Match `private var binding: SomeFragmentBinding? = null` or `private var _binding`
        binding_pattern = re.compile(r"private\s+var\s+(_?binding)\s*:\s*\w+Binding\?\s*=\s*null")

        for line in lines:
            if "class " in line and "Fragment(" in line:
                is_fragment = True
            
            match = binding_pattern.search(line)
            if match:
                binding_var_name = match.group(1)
                # Stop searching once found
                break
        
        # If not a Fragment or no nullable binding found, no need to continue checking
        if not is_fragment or not binding_var_name:
            return

        # 2. Identify binding-dependent methods (methods that likely access binding)
        binding_dependent_methods = self._find_binding_dependent_methods(lines, binding_var_name)
        
        # 3. Scan for unsafe calls to binding-dependent methods
        for issue in self._scan_for_unsafe_method_calls(lines, binding_var_name, binding_dependent_methods):
            yield issue

    def _find_binding_dependent_methods(self, lines: List[str], binding_var_name: str) -> set:
        """Find methods that directly access the binding variable."""
        dependent_methods = set()
        
        # Pattern to match method calls that access binding
        binding_access_pattern = re.compile(rf"\b{re.escape(binding_var_name)}\.[a-zA-Z_][a-zA-Z0-9_]*\s*\(")
        
        for line in lines:
            matches = binding_access_pattern.findall(line)
            for match in matches:
                # Extract method name from the match
                method_name = match.split('.')[-1].split('(')[0]
                dependent_methods.add(method_name)
        
        return dependent_methods

    def _scan_for_unsafe_method_calls(self, lines: List[str], binding_var_name: str, dependent_methods: set) -> Generator[Dict[str, Any], None, None]:
        """Scan for unsafe calls to binding-dependent methods."""
        # Lifecycle methods and callbacks where binding might be null
        risky_contexts = [
            'onEvents', 'onStart', 'onResume', 'onPause', 'onStop', 
            'onDestroyView', 'onDetach', 'onDestroy', 'onViewStateRestored'
        ]
        
        current_method = None
        in_risky_context = False
        in_safe_block = False
        safe_block_indent = -1
        
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped_line = line.strip()
            
            if not stripped_line or stripped_line.startswith("//"):
                continue
            
            # Track current method
            if "fun " in stripped_line and "(" in stripped_line:
                method_match = re.search(r"fun\s+([a-zA-Z_][a-zA-Z0-9_]*)", stripped_line)
                if method_match:
                    current_method = method_match.group(1)
                    in_risky_context = any(context in current_method for context in risky_contexts)
            
            # Track safe blocks (if statements with null checks)
            if f"if" in stripped_line and f"{binding_var_name} != null" in stripped_line:
                in_safe_block = True
                safe_block_indent = len(line) - len(line.lstrip(' '))
                continue
            
            # Exit safe block when indentation decreases or closing brace
            current_indent = len(line) - len(line.lstrip(' '))
            if in_safe_block and (stripped_line == "}" or current_indent < safe_block_indent):
                in_safe_block = False
                safe_block_indent = -1
            
            # Check for calls to binding-dependent methods
            for method_name in dependent_methods:
                method_call_pattern = re.compile(rf"\b{re.escape(method_name)}\s*\(")
                if method_call_pattern.search(line):
                    # Check if this is an unsafe call
                    if in_risky_context and not in_safe_block:
                        yield {
                            "line_num": line_num,
                            "code": line.strip(),
                            "detail": f"Unsafe call to binding-dependent method '{method_name}' in risky context '{current_method}' without null check for '{binding_var_name}'.",
                            "severity": "HIGH"
                        }
class UnsafeRtlLayoutRule(Rule):
    """
    Detects unsafe Android UI layout patterns that lack proper RTL (Right-to-Left) support.
    This rule specifically targets the pattern shown in the PR where UI components
    don't properly handle RTL layouts, which can cause layout issues in RTL languages.
    """
    issue_type = "Unsafe UI Layout Without RTL Support"
    suggestion = "UI components should properly support RTL layouts for international users. Use auto-mirrored icons, RTL-aware layouts, and proper direction handling to ensure consistent experience across all languages."
    
    # Pattern to match non-auto-mirrored icon usage
    NON_AUTO_MIRRORED_ICON_PATTERN = re.compile(r'Icons\.(Default|Filled|Outlined)\.(\w+)')
    
    # Pattern to match auto-mirrored icon usage (correct pattern)
    AUTO_MIRRORED_ICON_PATTERN = re.compile(r'Icons\.AutoMirrored\.(Default|Filled|Outlined)\.(\w+)')
    
    # Pattern to match manual RTL handling
    MANUAL_RTL_PATTERN = re.compile(r'(autoMirrorForRtl|layoutDirection|isRtl|isLtr)')
    
    # Pattern to match rotation and transform operations
    ROTATION_PATTERN = re.compile(r'\.rotate\s*\(\s*\w+\)')
    
    # Icons that commonly need RTL support
    DIRECTIONAL_ICONS = [
        'KeyboardArrowLeft', 'KeyboardArrowRight', 'ArrowBack', 'ArrowForward',
        'ChevronLeft', 'ChevronRight', 'NavigateBefore', 'NavigateNext',
        'PlayArrow', 'SkipPrevious', 'SkipNext', 'FastForward', 'FastRewind',
        'FirstPage', 'LastPage', 'KeyboardArrowUp', 'KeyboardArrowDown'
    ]
    
    # Layout components that should have RTL support
    RTL_SENSITIVE_COMPONENTS = [
        'Row', 'Column', 'Box', 'LazyRow', 'LazyColumn', 'FlowRow', 'FlowColumn'
    ]

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        # Only analyze Kotlin/Java files
        if not (file_path.endswith('.kt') or file_path.endswith('.java')):
            return
            
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped_line = line.strip()
            
            if not stripped_line or stripped_line.startswith("//"):
                continue
            
            # Check for non-auto-mirrored directional icons
            icon_match = self.NON_AUTO_MIRRORED_ICON_PATTERN.search(line)
            if icon_match:
                icon_name = icon_match.group(2)
                
                # Check if this is a directional icon that needs RTL support
                if self._is_directional_icon(icon_name):
                    # Check if there's proper RTL handling
                    if not self._has_rtl_support(lines, i, icon_name):
                        yield {
                            "line_num": line_num,
                            "code": line.strip(),
                            "detail": f"Directional icon '{icon_name}' used without proper RTL support. Consider using Icons.AutoMirrored or manual RTL handling for better internationalization.",
                            "severity": "MEDIUM"
                        }
            
            # Check for rotation operations that might need RTL consideration
            rotation_match = self.ROTATION_PATTERN.search(line)
            if rotation_match:
                # Check if there's RTL-aware rotation handling
                if not self._has_rtl_aware_rotation(lines, i):
                    yield {
                        "line_num": line_num,
                        "code": line.strip(),
                        "detail": "Rotation operation detected without RTL consideration. Ensure rotation behavior is appropriate for RTL layouts.",
                        "severity": "LOW"
                    }
    
    def _is_directional_icon(self, icon_name: str) -> bool:
        """Check if the icon is directional and needs RTL support."""
        return any(directional_icon in icon_name for directional_icon in self.DIRECTIONAL_ICONS)
    
    def _has_rtl_support(self, lines: List[str], current_line: int, icon_name: str) -> bool:
        """Check if there's proper RTL support for the icon usage."""
        # Look for auto-mirrored icon usage in the same context
        method_start = self._find_method_start(lines, current_line)
        method_end = self._find_method_end(lines, current_line)
        
        if method_start == -1 or method_end == -1:
            return False
        
        # Check for auto-mirrored icon usage or manual RTL handling
        for line_num in range(method_start, method_end + 1):
            line = lines[line_num]
            
            # Check for auto-mirrored icon usage
            if self.AUTO_MIRRORED_ICON_PATTERN.search(line):
                return True
            
            # Check for manual RTL handling
            if self.MANUAL_RTL_PATTERN.search(line):
                return True
        
        return False
    
    def _has_rtl_aware_rotation(self, lines: List[str], current_line: int) -> bool:
        """Check if rotation operation has RTL awareness."""
        # Look for RTL-aware rotation patterns
        method_start = self._find_method_start(lines, current_line)
        method_end = self._find_method_end(lines, current_line)
        
        if method_start == -1 or method_end == -1:
            return False
        
        # Check for RTL-aware rotation patterns
        rtl_rotation_patterns = [
            r'if\s*\(\s*.*isRtl.*\)',
            r'if\s*\(\s*.*layoutDirection.*\)',
            r'when\s*\(\s*.*layoutDirection.*\)',
            r'\.autoMirrorForRtl\s*\(\s*\)'
        ]
        
        for line_num in range(method_start, method_end + 1):
            line = lines[line_num]
            for pattern in rtl_rotation_patterns:
                if re.search(pattern, line):
                    return True
        
        return False
    
    def _find_method_start(self, lines: List[str], current_line: int) -> int:
        """Find the start of the current method."""
        for i in range(current_line, -1, -1):
            if "fun " in lines[i] and "(" in lines[i]:
                return i
        return -1
    
    def _find_method_end(self, lines: List[str], current_line: int) -> int:
        """Find the end of the current method."""
        brace_count = 0
        in_method = False
        
        for i in range(current_line, len(lines)):
            line = lines[i]
            if "{" in line:
                brace_count += line.count("{")
                in_method = True
            if "}" in line:
                brace_count -= line.count("}")
                if in_method and brace_count == 0:
                    return i
        return -1


class UnsafeStorageOperationRule(Rule):
    """
    Detects unsafe file operations that lack proper storage space checks.
    This rule specifically targets the pattern shown in the PR where file operations
    like downloads, installations, or cache operations don't check available storage space.
    """
    issue_type = "Unsafe Storage Operation Without Space Check"
    suggestion = "File operations should check available storage space before proceeding. Implement storage space validation to prevent installation failures and improve user experience."
    
    # Pattern to match file operations that might need storage space checks
    STORAGE_OPERATION_PATTERN = re.compile(r'(\w+)\.(download|install|update|write|save|create|copy|move)')
    
    # Pattern to match storage space checks
    STORAGE_CHECK_PATTERN = re.compile(r'(getEmptySpace|usableSpace|freeSpace|availableSpace|storageSpace)')
    
    # Pattern to match file size operations
    FILE_SIZE_PATTERN = re.compile(r'\.(size|length|getSize|getLength)\s*\(\s*\)')
    
    # File operations that typically require storage space checks
    STORAGE_INTENSIVE_OPERATIONS = [
        'download', 'install', 'update', 'write', 'save', 'create',
        'copy', 'move', 'extract', 'unzip', 'decompress', 'cache'
    ]
    
    # Storage-related APIs that should be checked
    STORAGE_APIS = [
        'getExternalStorageDirectory', 'getCacheDir', 'getFilesDir',
        'getDownloadDir', 'getDataDir', 'getExternalFilesDir'
    ]

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        # Only analyze Kotlin/Java files
        if not (file_path.endswith('.kt') or file_path.endswith('.java')):
            return
            
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped_line = line.strip()
            
            if not stripped_line or stripped_line.startswith("//"):
                continue
            
            # Check for storage-intensive operations
            operation_match = self.STORAGE_OPERATION_PATTERN.search(line)
            if operation_match:
                operation_name = operation_match.group(2)
                
                # Check if this is a storage-intensive operation that needs space validation
                if self._is_storage_intensive_operation(operation_name):
                    # Check if there's proper storage space validation
                    if not self._has_storage_space_check(lines, i, operation_name):
                        yield {
                            "line_num": line_num,
                            "code": line.strip(),
                            "detail": f"Storage operation '{operation_name}' detected without storage space validation. This can cause failures when device storage is insufficient.",
                            "severity": "MEDIUM"
                        }
            
            # Check for file size operations that might need storage validation
            size_match = self.FILE_SIZE_PATTERN.search(line)
            if size_match:
                # Check if there's storage space validation for file size operations
                if not self._has_storage_validation_for_size(lines, i):
                    yield {
                        "line_num": line_num,
                        "code": line.strip(),
                        "detail": "File size operation detected without storage space validation. Consider checking available space before processing large files.",
                        "severity": "LOW"
                    }
    
    def _is_storage_intensive_operation(self, operation_name: str) -> bool:
        """Check if the operation is storage-intensive and needs space validation."""
        return any(op.lower() in operation_name.lower() for op in self.STORAGE_INTENSIVE_OPERATIONS)
    
    def _has_storage_space_check(self, lines: List[str], current_line: int, operation_name: str) -> bool:
        """Check if there's proper storage space validation for the operation."""
        # Look for storage space checks in the current method
        method_start = self._find_method_start(lines, current_line)
        method_end = self._find_method_end(lines, current_line)
        
        if method_start == -1 or method_end == -1:
            return False
        
        # Check for storage space validation patterns
        storage_check_patterns = [
            r'getEmptySpace\s*\(\s*\)',
            r'usableSpace\s*[><=]',
            r'freeSpace\s*[><=]',
            r'availableSpace\s*[><=]',
            r'storageSpace\s*[><=]',
            r'Cache\.getEmptySpace',
            r'getUsableSpace\s*\(\s*\)',
            r'getFreeSpace\s*\(\s*\)'
        ]
        
        # Check for storage space validation in the method
        for line_num in range(method_start, method_end + 1):
            line = lines[line_num]
            for pattern in storage_check_patterns:
                if re.search(pattern, line):
                    return True
        
        return False
    
    def _has_storage_validation_for_size(self, lines: List[str], current_line: int) -> bool:
        """Check if there's storage validation for file size operations."""
        # Look for storage validation patterns around file size operations
        method_start = self._find_method_start(lines, current_line)
        method_end = self._find_method_end(lines, current_line)
        
        if method_start == -1 or method_end == -1:
            return False
        
        # Check for storage validation patterns
        validation_patterns = [
            r'if\s*\(\s*.*getEmptySpace.*\)',
            r'if\s*\(\s*.*usableSpace.*\)',
            r'if\s*\(\s*.*freeSpace.*\)',
            r'when\s*\(\s*.*storage.*\)',
            r'Cache\.getEmptySpace\s*\(\s*\)'
        ]
        
        for line_num in range(method_start, method_end + 1):
            line = lines[line_num]
            for pattern in validation_patterns:
                if re.search(pattern, line):
                    return True
        
        return False
    
    def _find_method_start(self, lines: List[str], current_line: int) -> int:
        """Find the start of the current method."""
        for i in range(current_line, -1, -1):
            if "fun " in lines[i] and "(" in lines[i]:
                return i
        return -1
    
    def _find_method_end(self, lines: List[str], current_line: int) -> int:
        """Find the end of the current method."""
        brace_count = 0
        in_method = False
        
        for i in range(current_line, len(lines)):
            line = lines[i]
            if "{" in line:
                brace_count += line.count("{")
                in_method = True
            if "}" in line:
                brace_count -= line.count("}")
                if in_method and brace_count == 0:
                    return i
        return -1


class UnsafeLibraryApiMigrationRule(Rule):
    """
    Detects unsafe usage of deprecated or changed APIs after library version upgrades.
    This rule specifically targets the pattern shown in the PR where library APIs
    have changed between versions (e.g., Coil v2 to v3) but code hasn't been updated.
    """
    issue_type = "Unsafe Library API Usage After Version Migration"
    suggestion = "Library APIs have changed between versions. Update deprecated or changed API calls to use the new version's API to prevent runtime errors and ensure compatibility."
    
    # Pattern to match old Coil v2 API usage
    COIL_V2_API_PATTERN = re.compile(r'(coil\.|ImageLoaderFactory|ImageLoader\.Builder|MemoryCache\.Builder|DiskCache\.Builder)')
    
    # Pattern to match new Coil v3 API usage
    COIL_V3_API_PATTERN = re.compile(r'(coil3\.|SingletonImageLoader\.Factory|PlatformContext|asImage\(\)|allowHardware\(\)|placeholder\(\)|error\(\))')
    
    # Pattern to match old API calls that need migration
    OLD_API_PATTERNS = [
        r'ImageLoaderFactory',
        r'ImageLoader\.Builder\(this\)',
        r'MemoryCache\.Builder\(this\)',
        r'DiskCache\.Builder\(\)',
        r'coil\.load',
        r'coil\.dispose',
        r'coil\.request\.ImageRequest',
        r'coil\.size\.Dimension',
        r'coil\.size\.Scale',
        r'addHeader\s*\(',
        r'error\s*\(\s*R\.drawable\.',
        r'placeholder\s*\(\s*R\.drawable\.'
    ]
    
    # Pattern to match new API calls that indicate proper migration
    NEW_API_PATTERNS = [
        r'SingletonImageLoader\.Factory',
        r'PlatformContext',
        r'asImage\s*\(\s*\)',
        r'allowHardware\s*\(\s*\)',
        r'coil3\.load',
        r'coil3\.dispose',
        r'coil3\.request\.ImageRequest',
        r'coil3\.size\.Dimension',
        r'coil3\.size\.Scale',
        r'httpHeaders\s*\(',
        r'error\s*\(\s*.*\.asImage\s*\(\s*\)',
        r'placeholder\s*\(\s*.*\.asImage\s*\(\s*\)'
    ]
    
    # Library migration patterns (can be extended for other libraries)
    LIBRARY_MIGRATIONS = {
        'coil': {
            'old_patterns': OLD_API_PATTERNS,
            'new_patterns': NEW_API_PATTERNS,
            'description': 'Coil image loading library v2 to v3 migration'
        }
    }

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        # Only analyze Kotlin/Java files
        if not (file_path.endswith('.kt') or file_path.endswith('.java')):
            return
            
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped_line = line.strip()
            
            if not stripped_line or stripped_line.startswith("//"):
                continue
            
            # Check for old API usage that needs migration
            for library_name, migration_info in self.LIBRARY_MIGRATIONS.items():
                for old_pattern in migration_info['old_patterns']:
                    if re.search(old_pattern, line):
                        # Check if there's proper migration in the same context
                        if not self._has_proper_migration(lines, i, migration_info['new_patterns']):
                            yield {
                                "line_num": line_num,
                                "code": line.strip(),
                                "detail": f"Old {library_name} API usage detected: '{old_pattern}'. {migration_info['description']} required. Update to use new API patterns.",
                                "severity": "HIGH"
                            }
            
            # Check for mixed old and new API usage (potential migration issues)
            if self._has_mixed_api_usage(line):
                yield {
                    "line_num": line_num,
                    "code": line.strip(),
                    "detail": "Mixed old and new API usage detected. Ensure consistent migration to prevent compatibility issues.",
                    "severity": "MEDIUM"
                }
    
    def _has_proper_migration(self, lines: List[str], current_line: int, new_patterns: List[str]) -> bool:
        """Check if there's proper migration to new API patterns."""
        # Look for new API usage in the current method
        method_start = self._find_method_start(lines, current_line)
        method_end = self._find_method_end(lines, current_line)
        
        if method_start == -1 or method_end == -1:
            return False
        
        # Check for new API patterns in the method
        for line_num in range(method_start, method_end + 1):
            line = lines[line_num]
            for pattern in new_patterns:
                if re.search(pattern, line):
                    return True
        
        return False
    
    def _has_mixed_api_usage(self, line: str) -> bool:
        """Check for mixed old and new API usage in the same line."""
        has_old_api = any(re.search(pattern, line) for pattern in self.OLD_API_PATTERNS)
        has_new_api = any(re.search(pattern, line) for pattern in self.NEW_API_PATTERNS)
        
        return has_old_api and has_new_api
    
    def _find_method_start(self, lines: List[str], current_line: int) -> int:
        """Find the start of the current method."""
        for i in range(current_line, -1, -1):
            if "fun " in lines[i] and "(" in lines[i]:
                return i
        return -1
    
    def _find_method_end(self, lines: List[str], current_line: int) -> int:
        """Find the end of the current method."""
        brace_count = 0
        in_method = False
        
        for i in range(current_line, len(lines)):
            line = lines[i]
            if "{" in line:
                brace_count += line.count("{")
                in_method = True
            if "}" in line:
                brace_count -= line.count("}")
                if in_method and brace_count == 0:
                    return i
        return -1


class UnsafeParentChildStateRule(Rule):
    """
    Detects unsafe parent-child state management patterns that can cause UI inconsistencies.
    This rule specifically targets the pattern shown in the PR where parent-child relationships
    are not properly maintained during state changes, especially in drag operations.
    """
    issue_type = "Unsafe Parent-Child State Management"
    suggestion = "Parent-child relationships should be properly maintained during state changes. Ensure parent state is updated when children change and vice versa to prevent UI inconsistencies."
    
    # Pattern to match parent-child state operations
    PARENT_CHILD_PATTERN = re.compile(r'(parent|child|children|isChild|findParent|changeParent)')
    
    # Pattern to match state change operations
    STATE_CHANGE_PATTERN = re.compile(r'(changeChecked|changeIsChild|updateItem|finishMove|startDrag)')
    
    # Pattern to match parent-child relationship checks
    RELATIONSHIP_CHECK_PATTERN = re.compile(r'(isChildOf|findChild|hasParent|getParent)')
    
    # Pattern to match unsafe parent-child operations
    UNSAFE_PARENT_CHILD_PATTERNS = [
        r'changeChecked\s*\(\s*\w+,\s*\w+,\s*true\s*\)',  # changeChecked without parent consideration
        r'changeIsChild\s*\(\s*\w+,\s*true\s*\)',  # changeIsChild without parent update
        r'finishMove\s*\(\s*\w+,\s*\w+,\s*\w+,\s*\w+\s*\)',  # finishMove without parent parameter
        r'startDrag\s*\(\s*\w+\s*\)',  # startDrag without parent tracking
        r'updateItem\s*\(\s*\w+,\s*\w+\s*\)'  # updateItem without parent-child validation
    ]
    
    # Pattern to match proper parent-child handling
    PROPER_PARENT_CHILD_PATTERNS = [
        r'if\s*\(\s*\w+\.isChild\s*\)',
        r'findParent\s*\(\s*\w+\s*\)',
        r'parentBefore\s*!=\s*null',
        r'parentAfter\s*!=\s*null',
        r'changeParentToo\s*=\s*true',
        r'changeChildren\s*=\s*true'
    ]

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        # Only analyze Kotlin/Java files
        if not (file_path.endswith('.kt') or file_path.endswith('.java')):
            return
            
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped_line = line.strip()
            
            if not stripped_line or stripped_line.startswith("//"):
                continue
            
            # Check for parent-child state operations
            if self.PARENT_CHILD_PATTERN.search(line) and self.STATE_CHANGE_PATTERN.search(line):
                # Check if this is an unsafe parent-child operation
                if self._is_unsafe_parent_child_operation(line):
                    # Check if there's proper parent-child handling
                    if not self._has_proper_parent_child_handling(lines, i):
                        yield {
                            "line_num": line_num,
                            "code": line.strip(),
                            "detail": "Parent-child state operation detected without proper relationship handling. This can cause UI inconsistencies during state changes.",
                            "severity": "MEDIUM"
                        }
            
            # Check for state changes that might affect parent-child relationships
            state_match = self.STATE_CHANGE_PATTERN.search(line)
            if state_match:
                # Check if there's proper parent-child validation
                if not self._has_parent_child_validation(lines, i):
                    yield {
                        "line_num": line_num,
                        "code": line.strip(),
                        "detail": "State change operation detected without parent-child relationship validation. Ensure proper parent-child state synchronization.",
                        "severity": "LOW"
                    }
    
    def _is_unsafe_parent_child_operation(self, line: str) -> bool:
        """Check if this is an unsafe parent-child operation."""
        for pattern in self.UNSAFE_PARENT_CHILD_PATTERNS:
            if re.search(pattern, line):
                return True
        return False
    
    def _has_proper_parent_child_handling(self, lines: List[str], current_line: int) -> bool:
        """Check if there's proper parent-child relationship handling."""
        # Look for proper parent-child handling in the current method
        method_start = self._find_method_start(lines, current_line)
        method_end = self._find_method_end(lines, current_line)
        
        if method_start == -1 or method_end == -1:
            return False
        
        # Check for proper parent-child handling patterns
        for line_num in range(method_start, method_end + 1):
            line = lines[line_num]
            for pattern in self.PROPER_PARENT_CHILD_PATTERNS:
                if re.search(pattern, line):
                    return True
        
        return False
    
    def _has_parent_child_validation(self, lines: List[str], current_line: int) -> bool:
        """Check if there's parent-child relationship validation."""
        # Look for parent-child validation patterns
        method_start = self._find_method_start(lines, current_line)
        method_end = self._find_method_end(lines, current_line)
        
        if method_start == -1 or method_end == -1:
            return False
        
        # Check for parent-child validation patterns
        validation_patterns = [
            r'if\s*\(\s*\w+\.isChild\s*\)',
            r'findParent\s*\(\s*\w+\s*\)',
            r'isChildOf\s*\(\s*\w+\s*\)',
            r'hasParent\s*\(\s*\)',
            r'getParent\s*\(\s*\)'
        ]
        
        for line_num in range(method_start, method_end + 1):
            line = lines[line_num]
            for pattern in validation_patterns:
                if re.search(pattern, line):
                    return True
        
        return False
    
    def _find_method_start(self, lines: List[str], current_line: int) -> int:
        """Find the start of the current method."""
        for i in range(current_line, -1, -1):
            if "fun " in lines[i] and "(" in lines[i]:
                return i
        return -1
    
    def _find_method_end(self, lines: List[str], current_line: int) -> int:
        """Find the end of the current method."""
        brace_count = 0
        in_method = False
        
        for i in range(current_line, len(lines)):
            line = lines[i]
            if "{" in line:
                brace_count += line.count("{")
                in_method = True
            if "}" in line:
                brace_count -= line.count("}")
                if in_method and brace_count == 0:
                    return i
        return -1
class IncompleteEqualsMethodRule(Rule):
    """
    Detects incomplete equals method implementations that don't compare all relevant fields.
    This rule specifically targets data classes and objects where equals method is missing
    field comparisons, which can lead to incorrect equality behavior.
    """
    issue_type = "Incomplete Equals Method Implementation"
    suggestion = "The equals method should compare all relevant fields to ensure proper equality behavior. Add missing field comparisons to prevent incorrect object equality."
    
    # Pattern to match equals method declarations
    EQUALS_METHOD_PATTERN = re.compile(r"(override\s+)?fun\s+equals\s*\(\s*other\s*:\s*Any\?\s*\)\s*:\s*Boolean")
    
    # Pattern to match field declarations in data classes
    FIELD_PATTERN = re.compile(r"val\s+(\w+)\s*:\s*\w+")
    
    # Pattern to match field comparisons in equals method
    FIELD_COMPARISON_PATTERN = re.compile(r"this\.(\w+)\s*==\s*other\.(\w+)")
    
    # Common field names that should be compared in equals
    COMMON_FIELDS = ['id', 'name', 'title', 'body', 'content', 'order', 'position', 'index', 'value', 'data']

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        # First, find all field declarations in the class
        class_fields = self._find_class_fields(lines)
        
        if not class_fields:
            return
        
        # Then, find equals method and check if all fields are compared
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped_line = line.strip()
            
            if not stripped_line or stripped_line.startswith("//"):
                continue
            
            # Check for equals method
            if self.EQUALS_METHOD_PATTERN.search(line):
                equals_method_start = i
                equals_method_end = self._find_method_end(lines, i)
                
                if equals_method_end == -1:
                    continue
                
                # Extract the equals method content
                equals_method_lines = lines[equals_method_start:equals_method_end + 1]
                equals_method_text = '\n'.join(equals_method_lines)
                
                # Find which fields are compared in the equals method
                compared_fields = self._find_compared_fields(equals_method_text)
                
                # Find missing field comparisons
                missing_fields = []
                for field in class_fields:
                    if field not in compared_fields:
                        missing_fields.append(field)
                
                # Report issues for missing field comparisons
                if missing_fields:
                    # Check if this is a data class (which should have complete equals)
                    is_data_class = self._is_data_class(lines, i)
                    
                    # Determine severity based on context
                    severity = "HIGH" if is_data_class else "MEDIUM"
                    
                    # Check if missing fields are important (common field names)
                    important_missing = [f for f in missing_fields if f in self.COMMON_FIELDS]
                    if important_missing:
                        severity = "HIGH"
                    
                    yield {
                        "line_num": line_num,
                        "code": line.strip(),
                        "detail": f"Incomplete equals method: missing field comparisons for {', '.join(missing_fields)}. This can cause incorrect equality behavior, especially for fields like {', '.join(important_missing) if important_missing else 'none'}.",
                        "severity": severity
                    }
    
    def _find_class_fields(self, lines: List[str]) -> List[str]:
        """Find all field declarations in the current class."""
        fields = []
        in_class = False
        class_indent = -1
        
        for line in lines:
            stripped_line = line.strip()
            
            # Check for class declaration
            if "class " in stripped_line and "(" in stripped_line:
                in_class = True
                class_indent = len(line) - len(line.lstrip(' '))
                continue
            
            # Exit class if indentation decreases
            current_indent = len(line) - len(line.lstrip(' '))
            if in_class and current_indent < class_indent:
                break
            
            # Find field declarations
            if in_class and stripped_line:
                field_match = self.FIELD_PATTERN.search(stripped_line)
                if field_match:
                    field_name = field_match.group(1)
                    # Skip common non-relevant fields
                    if field_name not in ['companion', 'object', 'const', 'val', 'var']:
                        fields.append(field_name)
        
        return fields
    
    def _find_compared_fields(self, equals_method_text: str) -> List[str]:
        """Find which fields are compared in the equals method."""
        compared_fields = []
        
        # Look for field comparisons
        matches = self.FIELD_COMPARISON_PATTERN.findall(equals_method_text)
        for match in matches:
            field1, field2 = match
            if field1 == field2:  # Same field comparison
                compared_fields.append(field1)
        
        return compared_fields
    
    def _is_data_class(self, lines: List[str], current_line: int) -> bool:
        """Check if the current class is a data class."""
        # Look backwards for class declaration
        for i in range(current_line, -1, -1):
            line = lines[i]
            if "class " in line:
                return "data class" in line
            elif line.strip().startswith("}"):
                break
        return False
    
    def _find_method_end(self, lines: List[str], current_line: int) -> int:
        """Find the end of the current method."""
        brace_count = 0
        in_method = False
        
        for i in range(current_line, len(lines)):
            line = lines[i]
            if "{" in line:
                brace_count += line.count("{")
                in_method = True
            if "}" in line:
                brace_count -= line.count("}")
                if in_method and brace_count == 0:
                    return i
        return -1


class MissingStateCheckRule(Rule):
    """
    Detects methods that perform operations without proper state checks.
    This rule specifically targets methods that should check loading states,
    empty states, or other critical state conditions before performing operations.
    """
    issue_type = "Missing State Check Before Operation"
    suggestion = "Add proper state checks (loading, empty, null) before performing operations to prevent race conditions, duplicate operations, or inconsistent states."
    
    # Pattern to match method calls that should have state checks
    OPERATION_PATTERNS = [
        re.compile(r"\.moveBaseNotes\s*\("),
        re.compile(r"\.delete\s*\("),
        re.compile(r"\.update\s*\("),
        re.compile(r"\.save\s*\("),
        re.compile(r"\.load\s*\("),
        re.compile(r"\.refresh\s*\("),
        re.compile(r"\.sync\s*\("),
        re.compile(r"\.upload\s*\("),
        re.compile(r"\.download\s*\("),
        re.compile(r"\.process\s*\("),
    ]
    
    # Pattern to match state variables that should be checked
    STATE_PATTERNS = [
        re.compile(r"\.loading\s*\.\s*value"),
        re.compile(r"\.isLoading\s*\(\s*\)"),
        re.compile(r"\.isEmpty\s*\(\s*\)"),
        re.compile(r"\.isEnabled\s*\(\s*\)"),
        re.compile(r"\.isBusy\s*\(\s*\)"),
        re.compile(r"\.isProcessing\s*\(\s*\)"),
        re.compile(r"\.enabled\s*\.\s*value"),
        re.compile(r"\.busy\s*\.\s*value"),
    ]
    
    # Pattern to match try-finally blocks
    TRY_FINALLY_PATTERN = re.compile(r"try\s*\{")
    FINALLY_PATTERN = re.compile(r"finally\s*\{")
    
    # Methods that commonly need state management
    STATE_MANAGEMENT_METHODS = [
        'moveNotes', 'deleteNotes', 'updateNote', 'saveNote', 'loadNotes',
        'refreshData', 'syncData', 'uploadData', 'downloadData', 'processData'
    ]

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped_line = line.strip()
            
            if not stripped_line or stripped_line.startswith("//"):
                continue
            
            # Check for operation patterns that should have state checks
            for pattern in self.OPERATION_PATTERNS:
                if pattern.search(line):
                    # Check if this operation has proper state checks
                    if not self._has_proper_state_checks(lines, i):
                        # Check if this is in a state management method
                        method_name = self._get_current_method_name(lines, i)
                        is_state_method = any(state_method in method_name for state_method in self.STATE_MANAGEMENT_METHODS)
                        
                        # Determine severity based on context
                        severity = "HIGH" if is_state_method else "MEDIUM"
                        
                        # Check if there are state variables available in the class
                        available_states = self._find_available_states(lines, i)
                        
                        detail = f"Operation '{pattern.search(line).group().strip()}' performed without state checks."
                        if available_states:
                            detail += f" Available state variables to check: {', '.join(available_states)}"
                        
                        yield {
                            "line_num": line_num,
                            "code": line.strip(),
                            "detail": detail,
                            "severity": severity
                        }
                    break
    
    def _has_proper_state_checks(self, lines: List[str], current_line: int) -> bool:
        """Check if the operation has proper state checks before it."""
        method_start = self._find_method_start(lines, current_line)
        method_end = self._find_method_end(lines, current_line)
        
        if method_start == -1 or method_end == -1:
            return False
        
        # Look for state checks before the operation
        for line_num in range(method_start, current_line):
            line = lines[line_num]
            
            # Check for early return with state condition
            if "return" in line and any(pattern.search(line) for pattern in self.STATE_PATTERNS):
                return True
            
            # Check for if statement with state condition
            if "if" in line and any(pattern.search(line) for pattern in self.STATE_PATTERNS):
                return True
            
            # Check for guard clauses
            if any(pattern.search(line) for pattern in self.STATE_PATTERNS):
                # Look for return or continue in the next few lines
                for next_line_num in range(line_num + 1, min(line_num + 5, current_line)):
                    next_line = lines[next_line_num]
                    if "return" in next_line or "continue" in next_line:
                        return True
        
        return False
    
    def _find_available_states(self, lines: List[str], current_line: int) -> List[str]:
        """Find available state variables in the current class."""
        available_states = []
        
        # Look for state variable declarations in the class
        class_start = self._find_class_start(lines, current_line)
        if class_start == -1:
            return available_states
        
        for line_num in range(class_start, current_line):
            line = lines[line_num]
            
            # Look for state variable declarations
            state_declarations = [
                r"val\s+(\w+)\s*=\s*NotNullLiveData",
                r"val\s+(\w+)\s*:\s*MutableLiveData",
                r"val\s+(\w+)\s*:\s*LiveData",
                r"private\s+val\s+(\w+)\s*=",
                r"val\s+(\w+)\s*=",
            ]
            
            for pattern_str in state_declarations:
                pattern = re.compile(pattern_str)
                match = pattern.search(line)
                if match:
                    var_name = match.group(1)
                    if var_name not in available_states:
                        available_states.append(var_name)
        
        return available_states
    
    def _get_current_method_name(self, lines: List[str], current_line: int) -> str:
        """Get the name of the current method."""
        for i in range(current_line, -1, -1):
            line = lines[i]
            if "fun " in line and "(" in line:
                method_match = re.search(r"fun\s+([a-zA-Z_][a-zA-Z0-9_]*)", line)
                if method_match:
                    return method_match.group(1)
        return ""
    
    def _find_class_start(self, lines: List[str], current_line: int) -> int:
        """Find the start of the current class."""
        for i in range(current_line, -1, -1):
            line = lines[i]
            if "class " in line and "(" in line:
                return i
        return -1
    
    def _find_method_start(self, lines: List[str], current_line: int) -> int:
        """Find the start of the current method."""
        for i in range(current_line, -1, -1):
            if "fun " in lines[i] and "(" in lines[i]:
                return i
        return -1
    
    def _find_method_end(self, lines: List[str], current_line: int) -> int:
        """Find the end of the current method."""
        brace_count = 0
        in_method = False
        
        for i in range(current_line, len(lines)):
            line = lines[i]
            if "{" in line:
                brace_count += line.count("{")
                in_method = True
            if "}" in line:
                brace_count -= line.count("}")
                if in_method and brace_count == 0:
                    return i
        return -1


class UnsafeCollectionAccessRule(Rule):
    """
    Detects unsafe collection access patterns that can cause NullPointerException or IndexOutOfBoundsException.
    This rule specifically targets direct access to collection elements without proper null checks or bounds validation.
    """
    issue_type = "Unsafe Collection Access Without Null/Bounds Check"
    suggestion = "Add null checks and bounds validation before accessing collection elements to prevent NullPointerException and IndexOutOfBoundsException."
    
    # Pattern to match unsafe collection access methods
    UNSAFE_ACCESS_PATTERNS = [
        re.compile(r"\.last\s*\(\s*\)"),
        re.compile(r"\.first\s*\(\s*\)"),
        re.compile(r"\.get\s*\(\s*(\w+)\s*\)"),
        re.compile(r"\.elementAt\s*\(\s*(\w+)\s*\)"),
        re.compile(r"\.removeAt\s*\(\s*(\w+)\s*\)"),
        re.compile(r"\.set\s*\(\s*(\w+)\s*,"),
        re.compile(r"\.add\s*\(\s*(\w+)\s*,"),
        re.compile(r"\.insert\s*\(\s*(\w+)\s*,"),
    ]
    
    # Pattern to match safe collection access methods
    SAFE_ACCESS_PATTERNS = [
        re.compile(r"\.lastOrNull\s*\(\s*\)"),
        re.compile(r"\.firstOrNull\s*\(\s*\)"),
        re.compile(r"\.getOrNull\s*\(\s*(\w+)\s*\)"),
        re.compile(r"\.elementAtOrNull\s*\(\s*(\w+)\s*\)"),
        re.compile(r"\.getOrElse\s*\(\s*(\w+)\s*,"),
        re.compile(r"\.elementAtOrElse\s*\(\s*(\w+)\s*,"),
    ]
    
    # Pattern to match collection size checks
    SIZE_CHECK_PATTERNS = [
        re.compile(r"\.isEmpty\s*\(\s*\)"),
        re.compile(r"\.isNotEmpty\s*\(\s*\)"),
        re.compile(r"\.size\s*[><=!]"),
        re.compile(r"\.count\s*\(\s*\)\s*[><=!]"),
    ]
    
    # Pattern to match null checks
    NULL_CHECK_PATTERNS = [
        re.compile(r"(\w+)\s*!=\s*null"),
        re.compile(r"(\w+)\s*==\s*null"),
        re.compile(r"(\w+)\s*\.\s*isNullOrEmpty\s*\(\s*\)"),
        re.compile(r"(\w+)\s*\.\s*isNotNullOrEmpty\s*\(\s*\)"),
    ]
    
    # Collections that commonly need safety checks
    COLLECTION_TYPES = ['List', 'MutableList', 'ArrayList', 'LinkedList', 'Set', 'MutableSet', 'HashSet', 'Map', 'MutableMap', 'HashMap']

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped_line = line.strip()
            
            if not stripped_line or stripped_line.startswith("//"):
                continue
            
            # Check for unsafe collection access patterns
            for pattern in self.UNSAFE_ACCESS_PATTERNS:
                if pattern.search(line):
                    # Extract the collection variable name
                    collection_var = self._extract_collection_variable(line, pattern)
                    if collection_var:
                        # Check if this access has proper safety checks
                        if not self._has_safety_checks(lines, i, collection_var):
                            # Check if this is a high-risk operation
                            is_high_risk = self._is_high_risk_operation(line, pattern)
                            
                            # Determine severity based on context
                            severity = "HIGH" if is_high_risk else "MEDIUM"
                            
                            # Check if there are safe alternatives available
                            safe_alternative = self._get_safe_alternative(pattern)
                            
                            detail = f"Unsafe collection access: '{pattern.search(line).group().strip()}' on '{collection_var}' without null/bounds check."
                            if safe_alternative:
                                detail += f" Consider using '{safe_alternative}' instead."
                            
                            yield {
                                "line_num": line_num,
                                "code": line.strip(),
                                "detail": detail,
                                "severity": severity
                            }
                    break
    
    def _extract_collection_variable(self, line: str, pattern: re.Pattern) -> str:
        """Extract the collection variable name from the unsafe access pattern."""
        # Look for patterns like: collection.last(), collection.get(index), etc.
        match = pattern.search(line)
        if not match:
            return ""
        
        # Find the collection variable name before the method call
        before_method = line[:match.start()]
        # Look for the last identifier before the method call
        words = before_method.split()
        if words:
            # Get the last word (which should be the collection variable)
            return words[-1].strip('.')
        
        return ""
    
    def _has_safety_checks(self, lines: List[str], current_line: int, collection_var: str) -> bool:
        """Check if there are proper safety checks for the collection access."""
        method_start = self._find_method_start(lines, current_line)
        method_end = self._find_method_end(lines, current_line)
        
        if method_start == -1 or method_end == -1:
            return False
        
        # Look for safety checks before the operation
        for line_num in range(method_start, current_line):
            line = lines[line_num]
            
            # Check for size checks
            for pattern in self.SIZE_CHECK_PATTERNS:
                if pattern.search(line) and collection_var in line:
                    # Look for return or continue in the next few lines
                    for next_line_num in range(line_num + 1, min(line_num + 5, current_line)):
                        next_line = lines[next_line_num]
                        if "return" in next_line or "continue" in next_line:
                            return True
            
            # Check for null checks
            for pattern in self.NULL_CHECK_PATTERNS:
                if pattern.search(line) and collection_var in line:
                    # Look for return or continue in the next few lines
                    for next_line_num in range(line_num + 1, min(line_num + 5, current_line)):
                        next_line = lines[next_line_num]
                        if "return" in next_line or "continue" in next_line:
                            return True
            
            # Check for safe access patterns
            for pattern in self.SAFE_ACCESS_PATTERNS:
                if pattern.search(line) and collection_var in line:
                    return True
        
        return False
    
    def _is_high_risk_operation(self, line: str, pattern: re.Pattern) -> bool:
        """Check if this is a high-risk operation that commonly causes crashes."""
        high_risk_patterns = [
            r"\.last\s*\(\s*\)",  # last() on empty list
            r"\.first\s*\(\s*\)",  # first() on empty list
            r"\.get\s*\(\s*(\w+)\s*\)",  # get() with invalid index
        ]
        
        for high_risk_pattern in high_risk_patterns:
            if re.search(high_risk_pattern, line):
                return True
        
        return False
    
    def _get_safe_alternative(self, pattern: re.Pattern) -> str:
        """Get the safe alternative for the unsafe access pattern."""
        pattern_str = pattern.pattern
        
        if "last" in pattern_str:
            return "lastOrNull()"
        elif "first" in pattern_str:
            return "firstOrNull()"
        elif "get" in pattern_str:
            return "getOrNull(index)"
        elif "elementAt" in pattern_str:
            return "elementAtOrNull(index)"
        elif "removeAt" in pattern_str:
            return "removeAtOrNull(index)"
        else:
            return ""
    
    def _find_method_start(self, lines: List[str], current_line: int) -> int:
        """Find the start of the current method."""
        for i in range(current_line, -1, -1):
            if "fun " in lines[i] and "(" in lines[i]:
                return i
        return -1
    
    def _find_method_end(self, lines: List[str], current_line: int) -> int:
        """Find the end of the current method."""
        brace_count = 0
        in_method = False
        
        for i in range(current_line, len(lines)):
            line = lines[i]
            if "{" in line:
                brace_count += line.count("{")
                in_method = True
            if "}" in line:
                brace_count -= line.count("}")
                if in_method and brace_count == 0:
                    return i
        return -1
class InconsistentStateManagementRule(Rule):
    """
    Detects inconsistent state management patterns that can lead to UI state inconsistencies.
    This rule specifically targets boolean flags and state variables that are not properly
    managed across different methods or conditions.
    """
    issue_type = "Inconsistent State Management"
    suggestion = "Ensure consistent state management by properly initializing, checking, and resetting state variables across all code paths."
    
    # Pattern to match boolean state variables
    BOOLEAN_STATE_PATTERNS = [
        re.compile(r"(private\s+)?(val|var)\s+(\w+)\s*:\s*Boolean"),
        re.compile(r"(private\s+)?(val|var)\s+(\w+)\s*=\s*(true|false)"),
        re.compile(r"(private\s+)?(val|var)\s+(\w+)\s*=\s*(\w+)\s*==\s*(\w+)"),
    ]
    
    # Pattern to match state assignments
    STATE_ASSIGNMENT_PATTERNS = [
        re.compile(r"(\w+)\s*=\s*(true|false)"),
        re.compile(r"(\w+)\s*=\s*!(\w+)"),
        re.compile(r"(\w+)\s*=\s*(\w+)\s*&&\s*(\w+)"),
        re.compile(r"(\w+)\s*=\s*(\w+)\s*\|\|\s*(\w+)"),
    ]
    
    # Pattern to match state checks in conditions
    STATE_CHECK_PATTERNS = [
        re.compile(r"if\s*\(\s*(\w+)\s*\)"),
        re.compile(r"if\s*\(\s*!(\w+)\s*\)"),
        re.compile(r"if\s*\(\s*(\w+)\s*&&\s*(\w+)\s*\)"),
        re.compile(r"if\s*\(\s*(\w+)\s*\|\|\s*(\w+)\s*\)"),
        re.compile(r"(\w+)\s*\|\|\s*(\w+)"),
        re.compile(r"(\w+)\s*&&\s*(\w+)"),
    ]
    
    # Pattern to match method calls that might affect state
    STATE_AFFECTING_METHODS = [
        re.compile(r"\.finish\s*\(\s*\)"),
        re.compile(r"\.clear\s*\(\s*\)"),
        re.compile(r"\.reset\s*\(\s*\)"),
        re.compile(r"\.dismiss\s*\(\s*\)"),
        re.compile(r"\.close\s*\(\s*\)"),
        re.compile(r"\.cancel\s*\(\s*\)"),
    ]
    
    # Common state variable names that need careful management
    STATE_VARIABLE_NAMES = [
        'showSystem', 'modalOpen', 'isVisible', 'isEnabled', 'isActive', 'isSelected',
        'isChecked', 'isExpanded', 'isCollapsed', 'isLoading', 'isBusy', 'isProcessing',
        'hasFocus', 'isFocused', 'isPressed', 'isHighlighted', 'isMarked'
    ]

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        # First, find all state variables in the file
        state_variables = self._find_state_variables(lines)
        
        if not state_variables:
            return
        
        # Then, analyze each state variable for inconsistencies
        for state_var in state_variables:
            for issue in self._analyze_state_variable(lines, state_var):
                yield issue
    
    def _find_state_variables(self, lines: List[str]) -> List[str]:
        """Find all state variables in the file."""
        state_vars = []
        
        for line in lines:
            # Check for boolean state variable declarations
            for pattern in self.BOOLEAN_STATE_PATTERNS:
                match = pattern.search(line)
                if match:
                    var_name = match.group(3)  # Extract variable name
                    if var_name in self.STATE_VARIABLE_NAMES or self._is_likely_state_variable(var_name):
                        state_vars.append(var_name)
        
        return list(set(state_vars))  # Remove duplicates
    
    def _is_likely_state_variable(self, var_name: str) -> bool:
        """Check if a variable name suggests it's a state variable."""
        state_indicators = ['show', 'is', 'has', 'can', 'should', 'modal', 'open', 'active', 'visible', 'enabled']
        return any(indicator in var_name.lower() for indicator in state_indicators)
    
    def _analyze_state_variable(self, lines: List[str], state_var: str) -> Generator[Dict[str, Any], None, None]:
        """Analyze a specific state variable for inconsistencies."""
        assignments = []
        checks = []
        resets = []
        
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped_line = line.strip()
            
            if not stripped_line or stripped_line.startswith("//"):
                continue
            
            # Find assignments to this state variable
            if f"{state_var} = " in stripped_line:
                assignments.append((line_num, stripped_line))
            
            # Find checks of this state variable
            if f"if ({state_var}" in stripped_line or f"if ({state_var})" in stripped_line or f"if (!{state_var}" in stripped_line:
                checks.append((line_num, stripped_line))
            
            # Find potential resets (assignments to false)
            if f"{state_var} = false" in stripped_line:
                resets.append((line_num, stripped_line))
        
        # Check for inconsistencies
        if assignments and not resets:
            # State is set but never reset
            yield {
                "line_num": assignments[0][0],
                "code": assignments[0][1],
                "detail": f"State variable '{state_var}' is assigned but never reset to false. This can lead to persistent state issues.",
                "severity": "MEDIUM"
            }
        
        if checks and not assignments:
            # State is checked but never set
            yield {
                "line_num": checks[0][0],
                "code": checks[0][1],
                "detail": f"State variable '{state_var}' is checked but never assigned. This may indicate missing state management.",
                "severity": "LOW"
            }
        
        if assignments and checks:
            # Check for complex conditional logic that might lead to inconsistencies
            for issue in self._check_complex_conditions(lines, state_var, assignments, checks):
                yield issue
    
    def _check_complex_conditions(self, lines: List[str], state_var: str, assignments: List[tuple], checks: List[tuple]) -> Generator[Dict[str, Any], None, None]:
        """Check for complex conditional logic that might lead to state inconsistencies."""
        for check_line_num, check_line in checks:
            # Look for complex conditions with multiple state variables
            if self._has_complex_condition(check_line):
                # Check if there are corresponding state management issues
                if not self._has_proper_state_management(lines, check_line_num, state_var):
                    yield {
                        "line_num": check_line_num,
                        "code": check_line,
                        "detail": f"Complex condition involving '{state_var}' without proper state management. This can lead to inconsistent UI states.",
                        "severity": "HIGH"
                    }
    
    def _has_complex_condition(self, line: str) -> bool:
        """Check if a line contains complex conditional logic."""
        complex_patterns = [
            r"(\w+)\s*&&\s*(\w+)",
            r"(\w+)\s*\|\|\s*(\w+)",
            r"(\w+)\s*&&\s*(\w+)\s*\|\|\s*(\w+)",
            r"(\w+)\s*\|\|\s*(\w+)\s*&&\s*(\w+)",
        ]
        
        for pattern in complex_patterns:
            if re.search(pattern, line):
                return True
        
        return False
    
    def _has_proper_state_management(self, lines: List[str], check_line_num: int, state_var: str) -> bool:
        """Check if there's proper state management around the complex condition."""
        # Look for state resets in the same method
        method_start = self._find_method_start(lines, check_line_num)
        method_end = self._find_method_end(lines, check_line_num)
        
        if method_start == -1 or method_end == -1:
            return False
        
        # Check for state resets in the method
        for line_num in range(method_start, method_end + 1):
            line = lines[line_num]
            if f"{state_var} = false" in line:
                return True
        
        return False
    
    def _find_method_start(self, lines: List[str], current_line: int) -> int:
        """Find the start of the current method."""
        for i in range(current_line, -1, -1):
            if "fun " in lines[i] and "(" in lines[i]:
                return i
        return -1
    
    def _find_method_end(self, lines: List[str], current_line: int) -> int:
        """Find the end of the current method."""
        brace_count = 0
        in_method = False
        
        for i in range(current_line, len(lines)):
            line = lines[i]
            if "{" in line:
                brace_count += line.count("{")
                in_method = True
            if "}" in line:
                brace_count -= line.count("}")
                if in_method and brace_count == 0:
                    return i
        return -1


class UnsafeJsonDeserializationRule(Rule):
    """
    Detects unsafe JSON deserialization in Room TypeConverters without proper exception handling.
    This rule specifically targets json.decodeFromString() calls that are not wrapped in try-catch blocks,
    which can cause app crashes when malformed JSON data is encountered.
    """
    issue_type = "Unsafe JSON Deserialization Without Exception Handling"
    suggestion = "Wrap json.decodeFromString() calls in try-catch blocks to handle SerializationException and prevent app crashes from malformed JSON data."
    
    # Pattern to match json.decodeFromString calls
    JSON_DECODE_PATTERN = re.compile(r"json\.decodeFromString\s*\(\s*serializer\s*\(\s*\)\s*,\s*(\w+)\s*\)")
    
    # Pattern to match try-catch blocks
    TRY_CATCH_PATTERN = re.compile(r"try\s*\{")
    CATCH_SERIALIZATION_PATTERN = re.compile(r"catch\s*\(\s*(\w+)?\s*:\s*SerializationException")
    
    # Pattern to match TypeConverter annotations
    TYPE_CONVERTER_PATTERN = re.compile(r"@TypeConverter")
    
    # Pattern to match return statements that might be in try-catch
    RETURN_PATTERN = re.compile(r"return\s+json\.decodeFromString")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        # Check if this is a TypeConverter file
        has_type_converter = False
        for line in lines:
            if self.TYPE_CONVERTER_PATTERN.search(line):
                has_type_converter = True
                break
        
        if not has_type_converter:
            return
        
        # Find all json.decodeFromString calls
        decode_calls = []
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped_line = line.strip()
            
            if not stripped_line or stripped_line.startswith("//"):
                continue
            
            if self.JSON_DECODE_PATTERN.search(stripped_line):
                decode_calls.append((line_num, stripped_line))
        
        if not decode_calls:
            return
        
        # Check each decode call for proper exception handling
        for line_num, line_content in decode_calls:
            if not self._has_proper_exception_handling(lines, line_num):
                # Determine severity based on context
                severity = self._determine_severity(lines, line_num)
                
                yield {
                    "line_num": line_num,
                    "code": line_content,
                    "detail": f"Unsafe JSON deserialization found: `{line_content}`. This call can throw SerializationException when malformed JSON data is encountered, potentially causing app crashes.",
                    "severity": severity
                }
    
    def _has_proper_exception_handling(self, lines: List[str], target_line: int) -> bool:
        """Check if the target line is properly wrapped in try-catch with SerializationException handling."""
        # Look backwards from target line to find try block
        try_start = None
        catch_found = False
        
        # Search backwards for try block
        for i in range(target_line - 1, -1, -1):
            line = lines[i].strip()
            if not line or line.startswith("//"):
                continue
            
            # Check for catch block with SerializationException
            if self.CATCH_SERIALIZATION_PATTERN.search(line):
                catch_found = True
            
            # Check for try block
            if self.TRY_CATCH_PATTERN.search(line):
                try_start = i + 1
                break
        
        # If we found a try block, check if it properly contains our target line
        if try_start and try_start < target_line:
            # Look for catch block after try
            for i in range(try_start, len(lines)):
                line = lines[i].strip()
                if not line or line.startswith("//"):
                    continue
                
                if self.CATCH_SERIALIZATION_PATTERN.search(line):
                    catch_found = True
                    break
                
                # If we hit a closing brace before finding catch, this try block is incomplete
                if line.startswith("}"):
                    break
        
        return catch_found
    
    def _determine_severity(self, lines: List[str], line_num: int) -> str:
        """Determine the severity of the issue based on context."""
        # Check if this is in a critical method (like database conversion)
        context_lines = lines[max(0, line_num - 5):min(len(lines), line_num + 5)]
        context_text = " ".join(context_lines)
        
        # High severity if it's in a TypeConverter method
        if "@TypeConverter" in context_text:
            return "HIGH"
        
        # Medium severity for other cases
        return "MEDIUM"


class UnsafeListDeduplicationRule(Rule):
    """
    Detects unsafe list operations without proper deduplication in Compose UI state management.
    This rule specifically targets list assignments and transformations that don't use distinctBy
    with safeKey, which can lead to duplicate entries in UI lists and poor user experience.
    """
    issue_type = "Unsafe List Operations Without Deduplication"
    suggestion = "Use distinctBy { e -> e.safeKey } to ensure list uniqueness and prevent duplicate entries in UI state."
    
    # Pattern to match list assignments without deduplication
    LIST_ASSIGNMENT_PATTERNS = [
        re.compile(r"entries\s*=\s*.*\.let\s*\{.*\}\s*\?:\s*emptyList\s*\(\s*\)"),
        re.compile(r"entries\s*=\s*.*\.filterNotNull\s*\(\s*\)"),
        re.compile(r"entries\s*=\s*.*\.map\s*\{.*\}\s*\.filterNotNull\s*\(\s*\)"),
    ]
    
    # Pattern to match list transformations that should include deduplication
    LIST_TRANSFORMATION_PATTERNS = [
        re.compile(r"\.filterNotNull\s*\(\s*\)"),
        re.compile(r"\.map\s*\{.*\}\s*\.filterNotNull\s*\(\s*\)"),
        re.compile(r"\.let\s*\{.*\}\s*\?:\s*emptyList"),
    ]
    
    # Pattern to match safeKey usage
    SAFE_KEY_PATTERN = re.compile(r"\.distinctBy\s*\{\s*e\s*->\s*e\.safeKey\s*\}")
    
    # Pattern to match ViewModel class declarations
    VIEW_MODEL_PATTERN = re.compile(r"class\s+\w+ViewModel\s*\(|class\s+\w+.*ViewModel\s*:")
    
    # Pattern to match Compose UI state updates
    STATE_UPDATE_PATTERNS = [
        re.compile(r"updateState\s*\{"),
        re.compile(r"copy\s*\(\s*entries\s*="),
        re.compile(r"entries\s*=\s*.*"),
    ]
    
    # Pattern to match list operations that should be deduplicated
    LIST_OPERATIONS = [
        re.compile(r"\.let\s*\{.*\}\s*\?:\s*emptyList"),
        re.compile(r"\.filterNotNull\s*\(\s*\)"),
        re.compile(r"\.map\s*\{.*\}\s*\.filterNotNull"),
    ]

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        # Check if this is a ViewModel file
        has_view_model = False
        for line in lines:
            if self.VIEW_MODEL_PATTERN.search(line):
                has_view_model = True
                break
        
        if not has_view_model:
            return
        
        # Find all list operations that should include deduplication
        list_operations = []
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped_line = line.strip()
            
            if not stripped_line or stripped_line.startswith("//"):
                continue
            
            # Check for list operations that should include deduplication
            if self._should_include_deduplication(stripped_line):
                list_operations.append((line_num, stripped_line))
        
        if not list_operations:
            return
        
        # Check each list operation for proper deduplication
        for line_num, line_content in list_operations:
            if not self._has_proper_deduplication(lines, line_num):
                # Determine severity based on context
                severity = self._determine_severity(lines, line_num)
                
                yield {
                    "line_num": line_num,
                    "code": line_content,
                    "detail": f"Unsafe list operation found: `{line_content}`. This operation should include distinctBy {{ e -> e.safeKey }} to prevent duplicate entries in UI state.",
                    "severity": severity
                }
    
    def _should_include_deduplication(self, line: str) -> bool:
        """Check if a line contains list operations that should include deduplication."""
        # Check for list assignments or transformations
        for pattern in self.LIST_OPERATIONS:
            if pattern.search(line):
                # Make sure it's not already using safeKey
                if not self.SAFE_KEY_PATTERN.search(line):
                    return True
        
        return False
    
    def _has_proper_deduplication(self, lines: List[str], target_line: int) -> bool:
        """Check if the target line or nearby lines include proper deduplication."""
        # Check the target line itself
        target_line_content = lines[target_line - 1].strip()
        if self.SAFE_KEY_PATTERN.search(target_line_content):
            return True
        
        # Check nearby lines for deduplication
        context_start = max(0, target_line - 3)
        context_end = min(len(lines), target_line + 3)
        
        for i in range(context_start, context_end):
            line = lines[i].strip()
            if self.SAFE_KEY_PATTERN.search(line):
                return True
        
        return False
    
    def _determine_severity(self, lines: List[str], line_num: int) -> str:
        """Determine the severity of the issue based on context."""
        # Check if this is in a critical state update method
        context_lines = lines[max(0, line_num - 5):min(len(lines), line_num + 5)]
        context_text = " ".join(context_lines)
        
        # High severity if it's in a state update method
        if "updateState" in context_text or "copy(" in context_text:
            return "HIGH"
        
        # Medium severity for other cases
        return "MEDIUM"


class UnsafeDateFormatterRule(Rule):
    """
    Detects unsafe date formatting patterns that use hardcoded string resources instead of localized formatting.
    This rule specifically targets DateTimeFormatter.ofPattern() calls that use string resources,
    which can lead to inconsistent date formatting across different locales and poor internationalization.
    """
    issue_type = "Unsafe Date Formatting Without Localization"
    suggestion = "Use DateTimeFormatter.ofLocalizedDate(FormatStyle.MEDIUM) instead of hardcoded string resources for better internationalization support."
    
    # Pattern to match DateTimeFormatter.ofPattern with string resources
    DATE_FORMATTER_PATTERN = re.compile(r"DateTimeFormatter\.ofPattern\s*\(\s*context\.getString\s*\(\s*R\.string\.\w+\s*\)\s*\)")
    
    # Pattern to match string resource definitions for date formats
    DATE_FORMAT_STRING_PATTERN = re.compile(r"<string\s+name=\"date_format\">.*</string>")
    
    # Pattern to match FormatStyle import
    FORMAT_STYLE_IMPORT_PATTERN = re.compile(r"import\s+java\.time\.format\.FormatStyle")
    
    # Pattern to match localized date formatter usage
    LOCALIZED_DATE_FORMATTER_PATTERN = re.compile(r"DateTimeFormatter\.ofLocalizedDate\s*\(\s*FormatStyle\.\w+\s*\)")
    
    # Pattern to match Java files
    JAVA_FILE_PATTERN = re.compile(r"\.java$")
    
    # Pattern to match Android resource files
    RESOURCE_FILE_PATTERN = re.compile(r"values.*/strings\.xml$")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        # Check if this is a Java file or resource file
        is_java_file = bool(self.JAVA_FILE_PATTERN.search(file_path))
        is_resource_file = bool(self.RESOURCE_FILE_PATTERN.search(file_path))
        
        if not (is_java_file or is_resource_file):
            return
        
        if is_java_file:
            # Analyze Java files for unsafe date formatting
            for issue in self._analyze_java_file(lines, file_path):
                yield issue
        elif is_resource_file:
            # Analyze resource files for date format strings
            for issue in self._analyze_resource_file(lines, file_path):
                yield issue
    
    def _analyze_java_file(self, lines: List[str], file_path: str) -> Generator[Dict[str, Any], None, None]:
        """Analyze Java files for unsafe date formatting patterns."""
        has_format_style_import = False
        has_localized_formatter = False
        
        # Check for FormatStyle import and localized formatter usage
        for line in lines:
            if self.FORMAT_STYLE_IMPORT_PATTERN.search(line):
                has_format_style_import = True
            if self.LOCALIZED_DATE_FORMATTER_PATTERN.search(line):
                has_localized_formatter = True
        
        # Find unsafe date formatter usage
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped_line = line.strip()
            
            if not stripped_line or stripped_line.startswith("//"):
                continue
            
            if self.DATE_FORMATTER_PATTERN.search(stripped_line):
                # Determine severity based on context
                severity = self._determine_severity(lines, line_num, has_format_style_import, has_localized_formatter)
                
                yield {
                    "line_num": line_num,
                    "code": stripped_line,
                    "detail": f"Unsafe date formatting found: `{stripped_line}`. This uses hardcoded string resources instead of localized formatting, which can lead to inconsistent date display across different locales.",
                    "severity": severity
                }
    
    def _analyze_resource_file(self, lines: List[str], file_path: str) -> Generator[Dict[str, Any], None, None]:
        """Analyze resource files for date format string definitions."""
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped_line = line.strip()
            
            if not stripped_line or stripped_line.startswith("<!--"):
                continue
            
            if self.DATE_FORMAT_STRING_PATTERN.search(stripped_line):
                yield {
                    "line_num": line_num,
                    "code": stripped_line,
                    "detail": f"Date format string resource found: `{stripped_line}`. Consider removing this and using localized date formatting instead for better internationalization support.",
                    "severity": "MEDIUM"
                }
    
    def _determine_severity(self, lines: List[str], line_num: int, has_format_style_import: bool, has_localized_formatter: bool) -> str:
        """Determine the severity of the issue based on context."""
        # High severity if FormatStyle is imported but not used properly
        if has_format_style_import and not has_localized_formatter:
            return "HIGH"
        
        # Medium severity for other cases
        return "MEDIUM"
class UnsafeForegroundServiceStartRule(Rule):
    """
    Detects unsafe foreground service lifecycle management where services are bound but not properly started.
    This rule specifically targets cases where startForegroundService() or startService() calls are commented out
    or missing, which can lead to service lifecycle issues and potential crashes.
    """
    issue_type = "Unsafe Foreground Service Lifecycle Management"
    suggestion = "Ensure proper service lifecycle by calling startForegroundService() or startService() before binding. Commented out service start calls should be reviewed and potentially restored."
    
    # Pattern to match bindService calls
    BIND_SERVICE_PATTERN = re.compile(r"bindService\s*\(")
    
    # Pattern to match startForegroundService calls (including commented out ones)
    START_FOREGROUND_SERVICE_PATTERN = re.compile(r"(//\s*)?(startForegroundService|startService)\s*\(")
    
    # Pattern to match ContextCompat.startForegroundService calls (including commented out ones)
    CONTEXT_COMPAT_START_PATTERN = re.compile(r"(//\s*)?ContextCompat\.startForegroundService\s*\(")
    
    # Pattern to match service binding flags
    BIND_AUTO_CREATE_PATTERN = re.compile(r"Context\.BIND_AUTO_CREATE")
    
    # Pattern to match Java files
    JAVA_FILE_PATTERN = re.compile(r"\.java$")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        # Only analyze Java files
        if not self.JAVA_FILE_PATTERN.search(file_path):
            return
        
        # Track service binding and starting patterns
        bind_service_lines = []
        start_service_lines = []
        commented_start_lines = []
        
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped_line = line.strip()
            
            if not stripped_line:
                continue
            
            # Check for bindService calls (only non-commented lines)
            if not stripped_line.startswith("//") and self.BIND_SERVICE_PATTERN.search(stripped_line):
                bind_service_lines.append((line_num, stripped_line))
            
            # Check for startForegroundService/startService calls (including commented ones)
            if self.START_FOREGROUND_SERVICE_PATTERN.search(stripped_line):
                if stripped_line.startswith("//"):
                    commented_start_lines.append((line_num, stripped_line))
                else:
                    start_service_lines.append((line_num, stripped_line))
            
            # Check for ContextCompat.startForegroundService calls (including commented ones)
            if self.CONTEXT_COMPAT_START_PATTERN.search(stripped_line):
                if stripped_line.startswith("//"):
                    commented_start_lines.append((line_num, stripped_line))
                else:
                    start_service_lines.append((line_num, stripped_line))
        
        # Analyze the patterns found
        for issue in self._analyze_service_patterns(bind_service_lines, start_service_lines, commented_start_lines, lines, file_path):
            yield issue
    
    def _analyze_service_patterns(self, bind_service_lines: List[tuple], start_service_lines: List[tuple], 
                                commented_start_lines: List[tuple], lines: List[str], file_path: str) -> Generator[Dict[str, Any], None, None]:
        """Analyze service binding and starting patterns for potential issues."""
        
        # Case 1: Has bindService but no startService calls
        if bind_service_lines and not start_service_lines:
            for line_num, code in bind_service_lines:
                # Check if this bindService call uses BIND_AUTO_CREATE
                has_auto_create = self._check_auto_create_flag(lines, line_num)
                
                severity = "HIGH" if not has_auto_create else "MEDIUM"
                detail = f"Service binding found without corresponding service start call: `{code}`. "
                if not has_auto_create:
                    detail += "Missing BIND_AUTO_CREATE flag and no explicit service start call."
                else:
                    detail += "Using BIND_AUTO_CREATE but explicit service start is recommended for foreground services."
                
                yield {
                    "line_num": line_num,
                    "code": code,
                    "detail": detail,
                    "severity": severity
                }
        
        # Case 2: Has commented out startService calls
        if commented_start_lines:
            for line_num, code in commented_start_lines:
                yield {
                    "line_num": line_num,
                    "code": code,
                    "detail": f"Commented out service start call found: `{code}`. This may indicate incomplete service lifecycle management that could lead to crashes or service not starting properly.",
                    "severity": "HIGH"
                }
        
        # Case 3: Has both bindService and startService but they might be in wrong order
        if bind_service_lines and start_service_lines:
            for bind_line_num, bind_code in bind_service_lines:
                # Check if there's a startService call before this bindService
                has_start_before_bind = self._check_start_before_bind(bind_line_num, start_service_lines)
                
                if not has_start_before_bind:
                    yield {
                        "line_num": bind_line_num,
                        "code": bind_code,
                        "detail": f"Service binding found without prior service start call: `{bind_code}`. For foreground services, startService should be called before bindService.",
                        "severity": "MEDIUM"
                    }
    
    def _check_auto_create_flag(self, lines: List[str], bind_line_num: int) -> bool:
        """Check if the bindService call uses BIND_AUTO_CREATE flag."""
        # Look for BIND_AUTO_CREATE in the same line or nearby lines
        start_line = max(0, bind_line_num - 3)  # Check 3 lines before
        end_line = min(len(lines), bind_line_num + 3)  # Check 3 lines after
        
        for i in range(start_line, end_line):
            if self.BIND_AUTO_CREATE_PATTERN.search(lines[i]):
                return True
        return False
    
    def _check_start_before_bind(self, bind_line_num: int, start_service_lines: List[tuple]) -> bool:
        """Check if there's a startService call before the bindService call."""
        for start_line_num, _ in start_service_lines:
            if start_line_num < bind_line_num:
                return True
        return False


class StrictServiceBindStartConsistencyRule(Rule):
    """
    Detects unsafe combination: binding a Service without Context.BIND_AUTO_CREATE while also
    starting the same Service via startForegroundService/startService (including ContextCompat).

    This mirrors the OpenTracks fix where they replaced an explicit foreground start with
    adding BIND_AUTO_CREATE to bind flags. Missing AUTO_CREATE together with explicit start
    can lead to ForegroundServiceDidNotStartInTimeException or crashes when stopping workouts.
    """
    issue_type = "Service bind/start lifecycle inconsistency (missing BIND_AUTO_CREATE)"
    suggestion = (
        "When binding to a Service that you also start via startForegroundService/startService, "
        "ensure bindService uses Context.BIND_AUTO_CREATE (preferably combined with debug flags). "
        "Alternatively, avoid redundant ContextCompat.startForegroundService if binding with AUTO_CREATE."
    )

    JAVA_FILE_PATTERN = re.compile(r"\.java$")

    # bindService(new Intent(context, MyService.class), conn, FLAGS)
    BIND_WITH_INTENT_PATTERN = re.compile(
        r"bindService\s*\(\s*new\s+Intent\s*\([^,]+,\s*([A-Za-z0-9_$.]+)\.class\s*\)\s*,\s*[^,]+,\s*([^\)]+)\)"
    )

    # startForegroundService(new Intent(context, MyService.class)) or startService(...)
    DIRECT_START_PATTERN = re.compile(
        r"(?:^|\W)(startForegroundService|startService)\s*\(\s*new\s+Intent\s*\([^,]+,\s*([A-Za-z0-9_$.]+)\.class\s*\)\s*\)"
    )

    # ContextCompat.startForegroundService(context, new Intent(context, MyService.class))
    CONTEXT_COMPAT_START_PATTERN = re.compile(
        r"ContextCompat\.startForegroundService\s*\(\s*[^,]+,\s*new\s+Intent\s*\([^,]+,\s*([A-Za-z0-9_$.]+)\.class\s*\)\s*\)"
    )

    BIND_AUTO_CREATE_PATTERN = re.compile(r"Context\.BIND_AUTO_CREATE")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        if not self.JAVA_FILE_PATTERN.search(file_path):
            return

        service_to_bind_occurrences: Dict[str, List[Dict[str, Any]]] = {}
        service_to_start_lines: Dict[str, List[int]] = {}

        for i, raw_line in enumerate(lines):
            line_num = i + 1
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("//"):
                continue

            # Collect bindService occurrences with captured flags
            bind_match = self.BIND_WITH_INTENT_PATTERN.search(stripped)
            if bind_match:
                service = bind_match.group(1)
                flags_expr = bind_match.group(2)
                has_auto_create_here = bool(self.BIND_AUTO_CREATE_PATTERN.search(flags_expr))
                # If flags are a variable/expression, scan a small window around for AUTO_CREATE
                if not has_auto_create_here:
                    has_auto_create_here = self._scan_nearby_for_auto_create(lines, i)

                service_to_bind_occurrences.setdefault(service, []).append({
                    "line_num": line_num,
                    "code": stripped,
                    "has_auto_create": has_auto_create_here,
                })

            # Collect direct start(...) occurrences
            start_match = self.DIRECT_START_PATTERN.search(stripped)
            if start_match:
                service = start_match.group(2)
                service_to_start_lines.setdefault(service, []).append(line_num)

            # Collect ContextCompat.startForegroundService occurrences
            compat_match = self.CONTEXT_COMPAT_START_PATTERN.search(stripped)
            if compat_match:
                service = compat_match.group(1)
                service_to_start_lines.setdefault(service, []).append(line_num)

        # Emit issues only when the same service is started and also bound without AUTO_CREATE
        for service, bind_list in service_to_bind_occurrences.items():
            if not bind_list:
                continue
            start_lines = service_to_start_lines.get(service, [])
            if not start_lines:
                continue

            first_start_line = min(start_lines)
            for bind in bind_list:
                if not bind["has_auto_create"]:
                    detail = (
                        f"Service '{service}' is started (line {first_start_line}) and also bound without "
                        f"Context.BIND_AUTO_CREATE (line {bind['line_num']}). This combination can cause "
                        f"foreground service timing issues/crashes. Add BIND_AUTO_CREATE to bind flags or "
                        f"avoid redundant foreground start when binding with AUTO_CREATE."
                    )
                    yield {
                        "line_num": bind["line_num"],
                        "code": bind["code"],
                        "detail": detail,
                        "severity": "HIGH",
                    }

    def _scan_nearby_for_auto_create(self, lines: List[str], idx: int) -> bool:
        start = max(0, idx - 4)
        end = min(len(lines), idx + 5)
        for j in range(start, end):
            if self.BIND_AUTO_CREATE_PATTERN.search(lines[j]):
                return True
        return False


class UnsafeDatabaseEntitySerializationRule(Rule):
    """
    Detects database entity classes that lack Serializable interface implementation.
    This rule specifically targets Room @Entity classes that don't implement Serializable,
    which can cause runtime errors when these objects need to be passed in Intents or serialized.
    """
    issue_type = "Database Entity Missing Serializable Implementation"
    suggestion = "Database entity classes should implement Serializable interface to ensure they can be safely passed in Intents and serialized. Add ': Serializable' to the class declaration."
    
    # Pattern to match Room @Entity annotations
    ENTITY_ANNOTATION_PATTERN = re.compile(r"@Entity\s*\(|@Entity")
    
    # Pattern to match class declarations
    CLASS_DECLARATION_PATTERN = re.compile(r"(data\s+)?class\s+(\w+)\s*\([^)]*\)\s*(?::\s*(\w+(?:<[^>]+>)?(?:\s*,\s*\w+(?:<[^>]+>)?)*))?\s*\{?")
    
    # Pattern to match Serializable interface
    SERIALIZABLE_PATTERN = re.compile(r":\s*Serializable|implements\s+Serializable")
    
    # Pattern to match import statements for Serializable
    SERIALIZABLE_IMPORT_PATTERN = re.compile(r"import\s+java\.io\.Serializable")
    
    # Pattern to match data class declarations
    DATA_CLASS_PATTERN = re.compile(r"data\s+class\s+(\w+)")
    
    # Common database entity field patterns that suggest the class might need serialization
    ENTITY_FIELD_PATTERNS = [
        re.compile(r"@PrimaryKey"),
        re.compile(r"@ColumnInfo"),
        re.compile(r"@ForeignKey"),
        re.compile(r"@Index"),
        re.compile(r"@Embedded"),
        re.compile(r"@Relation"),
    ]
    
    # Common field names that suggest the entity might be passed in Intents
    INTENT_RELATED_FIELDS = [
        'id', 'name', 'title', 'description', 'content', 'value',
        'timestamp', 'date', 'time', 'status', 'type', 'category'
    ]

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        # Only analyze Kotlin files (Room entities are typically in Kotlin)
        if not file_path.endswith('.kt'):
            return
        
        # Check if file contains Serializable import
        has_serializable_import = any(self.SERIALIZABLE_IMPORT_PATTERN.search(line) for line in lines)
        
        # Find all @Entity classes
        entity_classes = self._find_entity_classes(lines)
        
        for class_name, class_info in entity_classes.items():
            line_num = class_info['line_num']
            class_declaration = class_info['declaration']
            is_data_class = class_info['is_data_class']
            
            # Check if the class implements Serializable
            if not self._implements_serializable(class_declaration, has_serializable_import):
                # Check if this entity is likely to need serialization
                needs_serialization = self._needs_serialization(lines, class_name, is_data_class)
                
                if needs_serialization:
                    # Determine severity based on context
                    severity = self._determine_severity(is_data_class, class_name)
                    
                    yield {
                        "line_num": line_num,
                        "code": class_declaration.strip(),
                        "detail": f"Database entity class '{class_name}' lacks Serializable implementation. This can cause runtime errors when the object needs to be passed in Intents or serialized. Add ': Serializable' to the class declaration.",
                        "severity": severity
                    }
    
    def _find_entity_classes(self, lines: List[str]) -> Dict[str, Dict[str, Any]]:
        """Find all @Entity classes in the file."""
        entity_classes = {}
        current_entity = None
        
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped_line = line.strip()
            
            if not stripped_line or stripped_line.startswith("//"):
                continue
            
            # Check for @Entity annotation
            if self.ENTITY_ANNOTATION_PATTERN.search(stripped_line):
                current_entity = {'annotation_line': line_num, 'annotation': stripped_line}
                continue
            
            # Check for class declaration after @Entity
            if current_entity and "class " in stripped_line:
                class_match = self.CLASS_DECLARATION_PATTERN.search(stripped_line)
                if class_match:
                    class_name = class_match.group(2)
                    is_data_class = bool(class_match.group(1))
                    
                    entity_classes[class_name] = {
                        'line_num': line_num,
                        'declaration': stripped_line,
                        'is_data_class': is_data_class,
                        'annotation_line': current_entity['annotation_line']
                    }
                    current_entity = None
        
        return entity_classes
    
    def _implements_serializable(self, class_declaration: str, has_serializable_import: bool) -> bool:
        """Check if the class implements Serializable."""
        # Check if Serializable is in the class declaration
        if self.SERIALIZABLE_PATTERN.search(class_declaration):
            return True
        
        # Check if Serializable import exists (for Kotlin, this is often sufficient)
        if has_serializable_import:
            # In Kotlin, if Serializable is imported, it might be implemented
            # We'll be conservative and assume it's not implemented unless explicitly shown
            return False
        
        return False
    
    def _needs_serialization(self, lines: List[str], class_name: str, is_data_class: bool) -> bool:
        """Check if the entity class is likely to need serialization."""
        # Data classes are more likely to need serialization
        if is_data_class:
            return True
        
        # Check for entity field patterns that suggest database usage
        has_entity_fields = False
        for line in lines:
            for pattern in self.ENTITY_FIELD_PATTERNS:
                if pattern.search(line):
                    has_entity_fields = True
                    break
            if has_entity_fields:
                break
        
        if not has_entity_fields:
            return False
        
        # Check for field names that suggest the entity might be passed in Intents
        has_intent_related_fields = False
        for line in lines:
            for field_name in self.INTENT_RELATED_FIELDS:
                if f"val {field_name}" in line or f"var {field_name}" in line:
                    has_intent_related_fields = True
                    break
            if has_intent_related_fields:
                break
        
        # Check for common patterns that suggest the entity might be used in navigation or data passing
        has_navigation_patterns = any(
            "Intent" in line or "Bundle" in line or "Parcelable" in line or "Serializable" in line
            for line in lines
        )
        
        return has_entity_fields and (has_intent_related_fields or has_navigation_patterns)
    
    def _determine_severity(self, is_data_class: bool, class_name: str) -> str:
        """Determine the severity of the issue based on context."""
        # Data classes are more likely to be passed around, so higher severity
        if is_data_class:
            return "HIGH"
        
        # Check class name for common patterns that suggest it might be used in navigation
        navigation_indicators = ['model', 'entity', 'data', 'item', 'object', 'info']
        if any(indicator in class_name.lower() for indicator in navigation_indicators):
            return "MEDIUM"
        
        return "LOW"


class StrictKotlinRoomEntitySerializationRule(Rule):
    """
    Enforces that every Kotlin Room @Entity data class implements Serializable or Parcelable.
    Additionally, if the entity contains java.time types or DayOfWeek enums, suggests adding @Keep
    to prevent obfuscation/reflection issues when marshalling via Bundle/Parcel.

    This mirrors fixes where entities like Encouragement/Habit/HabitCheck/HabitReminder were updated
    to implement Serializable and, for complex field types, annotated with @Keep.
    """
    issue_type = "Room @Entity missing Serializable/Parcelable or missing @Keep for time/enums"
    suggestion = (
        "Make each @Entity data class implement java.io.Serializable or android.os.Parcelable. "
        "If the entity uses java.time types or enums like DayOfWeek, add @Keep to the class."
    )

    ENTITY_ANNOTATION_PATTERN = re.compile(r"@Entity\b")
    DATA_CLASS_DECL_PATTERN = re.compile(r"data\s+class\s+(\w+)\s*\(")
    CLASS_DECL_CAPTURE_PATTERN = re.compile(r"data\s+class\s+(\w+)\s*\(([^)]*)\)\s*(?::\s*([^{]+))?\s*[{)]")
    IMPLEMENTS_SERIALIZABLE_OR_PARCELABLE = re.compile(r"implements\s+Parcelable|implements\s+Serializable|:\s*Parcelable|:\s*Serializable|:\s*[^:]*\b(Parcelable|Serializable)\b")
    IMPORT_SERIALIZABLE = re.compile(r"import\s+java\.io\.Serializable")
    IMPORT_PARCELABLE = re.compile(r"import\s+android\.os\.Parcelable")
    KEEP_ANNOTATION = re.compile(r"@Keep\b")

    TIME_OR_ENUM_TYPES = [
        re.compile(r"\bjava\.time\."),
        re.compile(r"\bLocalDate\b"),
        re.compile(r"\bLocalTime\b"),
        re.compile(r"\bLocalDateTime\b"),
        re.compile(r"\bDayOfWeek\b"),
    ]

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        if not file_path.endswith('.kt'):
            return

        has_serializable_import = any(self.IMPORT_SERIALIZABLE.search(l) for l in lines)
        has_parcelable_import = any(self.IMPORT_PARCELABLE.search(l) for l in lines)

        entities = self._find_entity_classes(lines)
        for entity in entities:
            class_name = entity["class_name"]
            decl_line = entity["decl_line"]
            declaration = entity["declaration"]
            implements_interface = bool(self.IMPLEMENTS_SERIALIZABLE_OR_PARCELABLE.search(declaration))

            # Strict: every @Entity data class must implement Serializable/Parcelable
            if not implements_interface:
                yield {
                    "line_num": decl_line,
                    "code": declaration.strip(),
                    "detail": f"Room @Entity '{class_name}' does not implement Serializable or Parcelable.",
                    "severity": "HIGH",
                }

            # If fields include time/enum types, recommend @Keep if not present nearby
            if self._has_time_or_enum_fields(entity["params_raw"]) and not self._has_keep_nearby(lines, entity["decl_index"]):
                yield {
                    "line_num": decl_line,
                    "code": declaration.strip(),
                    "detail": f"Entity '{class_name}' uses java.time/enums; add @Keep to avoid marshalling/obfuscation issues.",
                    "severity": "MEDIUM",
                }

    def _find_entity_classes(self, lines: List[str]) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        saw_entity = False
        for i, raw in enumerate(lines):
            s = raw.strip()
            if not s or s.startswith("//"):
                continue
            if self.ENTITY_ANNOTATION_PATTERN.search(s):
                saw_entity = True
                continue
            if saw_entity and s.startswith("data class "):
                m = self.CLASS_DECL_CAPTURE_PATTERN.search(s)
                if m:
                    results.append({
                        "decl_index": i,
                        "decl_line": i + 1,
                        "class_name": m.group(1),
                        "params_raw": m.group(2) or "",
                        "implements_raw": (m.group(3) or "").strip(),
                        "declaration": s,
                    })
                saw_entity = False
        return results

    def _has_time_or_enum_fields(self, params_raw: str) -> bool:
        for p in self.TIME_OR_ENUM_TYPES:
            if p.search(params_raw):
                return True
        return False

    def _has_keep_nearby(self, lines: List[str], decl_index: int) -> bool:
        start = max(0, decl_index - 3)
        for j in range(start, decl_index + 1):
            if self.KEEP_ANNOTATION.search(lines[j]):
                return True
        return False


class StrictMlKitScannerVisibilityRule(Rule):
    """
    Detects unsafe visibility condition setup for embedded ML Kit scanner that can cause
    IllegalArgumentException("The detector does not exist") when re-entering pages.

    Specifically checks calls of:
      embeddedFragmentScanner.setScannerVisibilityLive(liveData, visibilityBoolean)
    and enforces that the boolean argument must be a strict conjunction of:
      backFromChooseProductPage && (productDetails != null || isProductWillBeFilled()) && isScannerVisible()

    Any omission (e.g., using only backFromChooseProductPage, or a ternary that collapses to raw boolean)
    will be reported as HIGH severity.
    """
    issue_type = "Unsafe ML Kit scanner visibility condition"
    suggestion = (
        "Ensure second parameter is a strict AND of: backFromChooseProductPage && "
        "(formData.productDetailsLive.value != null || viewModel.isProductWillBeFilled()) && "
        "formData.isScannerVisible()."
    )

    JAVA_FILE_PATTERN = re.compile(r"\.java$")
    KOTLIN_FILE_PATTERN = re.compile(r"\.kt$")

    METHOD_CALL_PATTERN = re.compile(
        r"embeddedFragmentScanner\.setScannerVisibilityLive\s*\(\s*([^,]+),\s*(.+?)\)\s*;?"
    )

    # Required sub-conditions (as relaxed regexes to allow minor formatting differences)
    COND_BACK_FROM_CHOOSE = re.compile(r"\bbackFromChooseProductPage\b")
    COND_PRODUCT_DETAILS_OR_WILL_FILL = re.compile(
        r"\((?:[^()]*?getProductDetailsLive\(\)\.getValue\(\)\s*!\=\s*null[^)]*?|[^()]*?isProductWillBeFilled\s*\(\)[^)]*?)\)"
    )
    COND_IS_SCANNER_VISIBLE = re.compile(r"formData\(\)\.isScannerVisible\s*\(\)|getFormData\(\)\.isScannerVisible\s*\(\)")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        if not (self.JAVA_FILE_PATTERN.search(file_path) or self.KOTLIN_FILE_PATTERN.search(file_path)):
            return

        for i, raw in enumerate(lines):
            s = raw.strip()
            if not s or s.startswith("//"):
                continue

            m = self.METHOD_CALL_PATTERN.search(s)
            if not m:
                continue

            second_arg = m.group(2)
            # Must be an AND chain covering all three required subconditions
            has_back = bool(self.COND_BACK_FROM_CHOOSE.search(second_arg))
            has_prod_or_fill = bool(self.COND_PRODUCT_DETAILS_OR_WILL_FILL.search(second_arg))
            has_visible = bool(self.COND_IS_SCANNER_VISIBLE.search(second_arg))
            is_and_chain = '&&' in second_arg

            if not (is_and_chain and has_back and has_prod_or_fill and has_visible):
                yield {
                    "line_num": i + 1,
                    "code": s,
                    "detail": (
                        "Second argument of setScannerVisibilityLive must be: "
                        "backFromChooseProductPage && (productDetails != null || isProductWillBeFilled()) && isScannerVisible()."
                    ),
                    "severity": "HIGH",
                }


class StrictQuickTileForegroundStartRule(Rule):
    """
    Detects Quick Settings Tile services starting foreground work directly when app is backgrounded
    on Android 14+, without using an Activity workaround (startActivityAndCollapse with PendingIntent).
    """
    issue_type = "QuickTile starts service in background on Android 14+ without workaround"
    suggestion = "For Android 14+, start an intermediate Activity via startActivityAndCollapse(PendingIntent) to initiate foreground work."

    TILE_SERVICE_PATTERN = re.compile(r"class\s+\w*Tile\w*\s*:\s*\w*TileService")
    DIRECT_ENABLE_CALL_PATTERN = re.compile(r"\.(enable\(|enableMonitor\(|start\()")
    WORKAROUND_CALL_PATTERN = re.compile(r"startActivityAndCollapse\s*\(.*PendingIntent")
    WORKAROUND_HELPER_PATTERN = re.compile(r"isForegroundWorkaroundNeeded\s*\(\)|startWorkaround\s*\(")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        if not file_path.endswith('.kt'):
            return

        in_tile = False
        for i, raw in enumerate(lines):
            s = raw.strip()
            if not s or s.startswith("//"):
                continue

            if self.TILE_SERVICE_PATTERN.search(s):
                in_tile = True
                continue

            if in_tile and "class " in s:
                in_tile = False

            if in_tile and ("override fun start(" in s or "override fun onClick(" in s or "override fun onStartListening(" in s):
                # Look ahead a small window for either workaround or direct enable
                window_end = min(len(lines), i + 20)
                window_text = "\n".join(x.strip() for x in lines[i:window_end])
                has_workaround = bool(self.WORKAROUND_CALL_PATTERN.search(window_text) or self.WORKAROUND_HELPER_PATTERN.search(window_text))
                has_direct_enable = bool(self.DIRECT_ENABLE_CALL_PATTERN.search(window_text))
                if has_direct_enable and not has_workaround:
                    yield {
                        "line_num": i + 1,
                        "code": s,
                        "detail": "Tile triggers foreground work directly; add Android 14 workaround with startActivityAndCollapse(PendingIntent).",
                        "severity": "HIGH",
                    }


class StrictTilePendingIntentWorkaroundRule(Rule):
    """
    Detects missing PendingIntent/Activity pattern used to start foreground work from tiles:
    - helper pendingIntent(context, id) in companion object
    - startActivityAndCollapse(pendingIntent)
    - proper FLAG_IMMUTABLE | FLAG_CANCEL_CURRENT
    """
    issue_type = "Missing QuickTile PendingIntent + startActivityAndCollapse workaround"
    suggestion = "Provide TileActivity.pendingIntent(...) and call startActivityAndCollapse(pendingIntent) on Android 14+."

    PENDING_INTENT_CREATION_PATTERN = re.compile(r"PendingIntent\.getActivity\s*\(.*PendingIntent\.(FLAG_IMMUTABLE|FLAG_UPDATE_CURRENT).*(\|\s*PendingIntent\.(FLAG_IMMUTABLE|FLAG_CANCEL_CURRENT))?")
    START_AND_COLLAPSE_PATTERN = re.compile(r"startActivityAndCollapse\s*\(\s*pendingIntent\s*\)")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        if not file_path.endswith('.kt'):
            return

        content = "\n".join(lines)
        has_pending_intent = bool(self.PENDING_INTENT_CREATION_PATTERN.search(content))
        has_start_and_collapse = bool(self.START_AND_COLLAPSE_PATTERN.search(content))

        if has_pending_intent and not has_start_and_collapse:
            # Likely created a pending intent but not used with startActivityAndCollapse
            line_num = 1
            yield {
                "line_num": line_num,
                "code": "PendingIntent workaround incomplete",
                "detail": "Create PendingIntent for TileActivity but also call startActivityAndCollapse(pendingIntent) to trigger foreground work.",
                "severity": "MEDIUM",
            }
# Qt / C++ specific rules

class StrictQtModelDbMutexRule(Rule):
    """
    Detects unprotected QSqlDatabase/QSqlQuery access in Qt model/private classes that should be
    guarded by QMutex/QMutexLocker to avoid crashes when accessed from multiple threads.

    Mirrors fixes adding QMutex + QMutexLocker around tag/preset CRUD in BrushPresetTagModel::Private.
    """
    issue_type = "Qt SQL access without QMutex/QMutexLocker protection"
    suggestion = (
        "Add a QMutex member to the class and guard each method that touches QSqlDatabase/QSqlQuery "
        "with QMutexLocker locker{&m_mutex};"
    )

    CPP_FILE_PATTERN = re.compile(r"\.(cpp|cc|cxx|hpp|hh|hxx)$")
    INCLUDES_QT_SQL = re.compile(r"#\s*include\s*<QSql(Database|Query|Error)>|QSql(Database|Query|Error)")
    HAS_QMUTEX = re.compile(r"\bQMutex\b|#\s*include\s*<QMutex>|#\s*include\s*<QMutexLocker>")
    HAS_QMUTEXLOCKER = re.compile(r"\bQMutexLocker\b")
    CLASS_PRIVATE_PATTERN = re.compile(r"class\s+([A-Za-z0-9_:]+)::Private\b|class\s+\w+\s*\{")
    SQL_USAGE_PATTERN = re.compile(r"\bQSqlQuery\b|\bread\w*\(|\bexec\s*\(|prepare\s*\(|lastInsertId\s*\(|query\.next\s*\(")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        if not self.CPP_FILE_PATTERN.search(file_path):
            return

        content = "\n".join(lines)
        if not self.INCLUDES_QT_SQL.search(content):
            return

        has_mutex_decl = bool(self.HAS_QMUTEX.search(content))

        # Find SQL usages that are not preceded by a QMutexLocker in a small window
        for i, raw in enumerate(lines):
            s = raw.strip()
            if not s or s.startswith("//"):
                continue
            if not self.SQL_USAGE_PATTERN.search(s):
                continue

            # Look back a few lines for locker
            start = max(0, i - 6)
            window = "\n".join(x.strip() for x in lines[start:i+1])
            has_locker_nearby = bool(self.HAS_QMUTEXLOCKER.search(window))

            if not has_locker_nearby:
                detail = "QSqlDatabase/QSqlQuery access without nearby QMutexLocker; add QMutex member and guard method scope."
                severity = "HIGH" if has_mutex_decl else "MEDIUM"
                yield {
                    "line_num": i + 1,
                    "code": s,
                    "detail": detail,
                    "severity": severity,
                }
class StrictQtSqlExplicitBindIndexRule(Rule):
    """
    Detects QVariantList parameter binding loops that use addBindValue(param) without explicit index,
    recommending bindValue(i, params[i]) to ensure stable positional binding consistency across Qt versions.
    """
    issue_type = "Qt SQL parameter binding without explicit index"
    suggestion = (
        "In loops over QVariantList params, prefer query.bindValue(i, params[i]) instead of addBindValue(param)."
    )

    CPP_FILE_PATTERN = re.compile(r"\.(cpp|cc|cxx)$")
    EXEC_FUNC_SIGNATURE = re.compile(r"\bbool\s+exec\s*\(\s*QSqlQuery\s*&\s*query\s*,\s*const\s+QString\s*&\s*sql\s*,\s*const\s+QVariant(List|List<\s*QVariant\s*>)\s*&\s*params\s*\)")
    FOR_RANGE_PARAMS = re.compile(r"for\s*\(\s*const\s+QVariant\s*&\s*\w+\s*:\s*params\s*\)")
    ADD_BIND_VALUE = re.compile(r"query\.addBindValue\s*\(")
    BIND_VALUE_INDEXED = re.compile(r"query\.bindValue\s*\(\s*\w+\s*,")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        if not self.CPP_FILE_PATTERN.search(file_path):
            return

        # Track if inside exec signature and find binding style inside
        inside_exec = False
        exec_start = 0
        for i, raw in enumerate(lines):
            s = raw.strip()
            if not s:
                continue

            if self.EXEC_FUNC_SIGNATURE.search(s):
                inside_exec = True
                exec_start = i
                continue

            if inside_exec:
                # rudimentary end detection
                if s.startswith("}"):
                    inside_exec = False
                    continue

                # detect range-for with addBindValue
                if self.FOR_RANGE_PARAMS.search(s) or "for(" in s and "params" in s:
                    # look ahead a small window
                    end = min(len(lines), i + 8)
                    window = "\n".join(x.strip() for x in lines[i:end])
                    uses_add = bool(self.ADD_BIND_VALUE.search(window))
                    has_indexed = bool(self.BIND_VALUE_INDEXED.search(window))
                    if uses_add and not has_indexed:
                        yield {
                            "line_num": i + 1,
                            "code": s,
                            "detail": "Loop binds params via addBindValue without explicit index; prefer bindValue(i, params[i]).",
                            "severity": "MEDIUM",
                        }


class StrictSqlLikeEscapingRule(Rule):
    """
    Detects unsafe concatenation of unescaped variables into SQL LIKE clauses, particularly when
    using single-quoted patterns and user/category-provided strings that may include `'`.

    Mirrors the fix that replaced:
        ... " LIKE '" + categoryName + ":%' "
    with:
        - quote style change to double quotes for the SQL literal, and
        - escaping embedded quotes in the variable (categoryName.replace("\"", "\"\""))

    Strongly recommends parameterization instead of string concatenation.
    """
    issue_type = "Unsafe SQL LIKE concatenation without escaping/parameterization"
    suggestion = (
        "Avoid concatenating variables into LIKE; use parameterized queries. If unavoidable, "
        "escape quotes properly and prefer double-quoted SQL literals while doubling embedded quotes."
    )

    JAVA_FILE_PATTERN = re.compile(r"\.java$")
    # Keep a simple broad detector; precise LIKE_CONCAT_PATTERN removed due to escaping complexity
    # Fallback broader pattern: LIKE '<literal>' ... + <var> + ... ':%'
    BROAD_LIKE_CONCAT = re.compile(r"LIKE\s*'[^']*'\s*\+\s*([A-Za-z0-9_$.]+)\s*\+\s*'[:%]")
    ESCAPE_REPLACE_PATTERN = re.compile(r"\.replace\s*\(\s*\\\"\\\"\s*,\s*\\\"\\\"\\\"\\\"\s*\)")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        if not self.JAVA_FILE_PATTERN.search(file_path):
            return

        for i, raw in enumerate(lines):
            s = raw.strip()
            if not s or s.startswith("//"):
                continue

            if "LIKE" not in s or "+" not in s:
                continue

            matched = self.BROAD_LIKE_CONCAT.search(s)
            if not matched:
                continue

            # Check nearby lines for escaping attempts
            start = max(0, i - 3)
            end = min(len(lines), i + 4)
            window = "\n".join(x.strip() for x in lines[start:end])
            has_escape = ".replace(\"\", \"\"\")" in window or ".replace(\'\', \'\'\')" in window

            if not has_escape:
                yield {
                    "line_num": i + 1,
                    "code": s,
                    "detail": (
                        "Unsafe LIKE concatenation with potential unescaped quotes. Use parameterized query "
                        "or escape/double quotes before concatenation."
                    ),
                    "severity": "HIGH",
                }


class StrictSafeUriParsingRule(Rule):
    """
    Detects unsafe java.net.URI parsing without exception handling/null-guard.

    Targets patterns like:
        val uri = URI(addressUri)
        val uri = URI.create(addressUri)

    and requires either:
        - try/catch wrapping that returns a safe fallback (e.g., WrongUri), or
        - runCatching { URI(...) }.getOrNull() with null-check / elvis return.
    """
    issue_type = "Unsafe URI parsing without exception handling"
    suggestion = (
        "Wrap URI(...) in try/catch (or use runCatching) and return a safe fallback when parsing fails, "
        "e.g., return AddressUriResult.WrongUri."
    )

    KT_OR_JAVA = re.compile(r"\.(kt|java)$")
    NEW_URI_PATTERN = re.compile(r"\bURI\s*\(\s*[^\)]+\)\s*")
    URI_CREATE_PATTERN = re.compile(r"\bURI\s*\.\s*create\s*\(\s*[^\)]+\)\s*")
    RUN_CATCHING_PATTERN = re.compile(r"runCatching\s*\(")
    TRY_PATTERN = re.compile(r"\btry\b")
    ELVIS_NULL_RETURN_PATTERN = re.compile(r"\?\:\s*\w+")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        if not self.KT_OR_JAVA.search(file_path):
            return

        for i, raw in enumerate(lines):
            s = raw.strip()
            if not s or s.startswith("//"):
                continue

            has_new = bool(self.NEW_URI_PATTERN.search(s)) or bool(self.URI_CREATE_PATTERN.search(s))
            if not has_new:
                continue

            # Examine a small window around the construction for try/runCatching or null-guard elvis
            start = max(0, i - 4)
            end = min(len(lines), i + 5)
            window_lines = [x.strip() for x in lines[start:end]]
            window = "\n".join(window_lines)

            has_try = bool(self.TRY_PATTERN.search(window))
            has_run_catching = bool(self.RUN_CATCHING_PATTERN.search(window))
            has_elvis = bool(self.ELVIS_NULL_RETURN_PATTERN.search(window))

            # If neither try/runCatching present, or no elvis null-guard on result, it's unsafe
            if not (has_try or has_run_catching or has_elvis):
                yield {
                    "line_num": i + 1,
                    "code": s,
                    "detail": "URI parsing is not guarded; parsing may throw. Add try/catch or runCatching with fallback.",
                    "severity": "HIGH",
                }


class StrictCryptoAddressValidationCatchRule(Rule):
    """
    Detects unsafe exception handling for crypto address validation where only Exception is caught,
    but library methods may throw non-Exception Throwables (e.g., Errors), leading to crashes.

    Targets patterns like:
        try { Address.fromBase58(reference); return true } catch (e: Exception) { return false }

    Requires catching Throwable (or adding an additional catch for Throwable) or using a safe wrapper
    that converts any Throwable into a failure result.
    """
    issue_type = "Crypto address validation catches Exception instead of Throwable"
    suggestion = (
        "Broaden catch to Throwable (e.g., catch (e: Throwable) { return false }) or use a safe wrapper."
    )

    KT_OR_JAVA = re.compile(r"\.(kt|java)$")
    RISKY_FROM_BASE58 = re.compile(r"\bAddress\s*\.\s*fromBase58\s*\(")
    CATCH_EXCEPTION = re.compile(r"catch\s*\(\s*(?:java\.lang\.)?Exception\b")
    CATCH_THROWABLE = re.compile(r"catch\s*\(\s*(?:java\.lang\.)?Throwable\b")
    TRY_PATTERN = re.compile(r"\btry\b")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        if not self.KT_OR_JAVA.search(file_path):
            return

        for i, raw in enumerate(lines):
            s = raw.strip()
            if not s or s.startswith("//"):
                continue

            if not self.RISKY_FROM_BASE58.search(s):
                continue

            # Look around for try/catch context
            start = max(0, i - 6)
            end = min(len(lines), i + 10)
            window_lines = [x.strip() for x in lines[start:end]]
            window = "\n".join(window_lines)

            has_try = bool(self.TRY_PATTERN.search(window))
            has_catch_exception = bool(self.CATCH_EXCEPTION.search(window))
            has_catch_throwable = bool(self.CATCH_THROWABLE.search(window))

            if has_try and has_catch_exception and not has_catch_throwable:
                yield {
                    "line_num": i + 1,
                    "code": s,
                    "detail": "Address.fromBase58 guarded only by catch(Exception); broaden to catch(Throwable) to avoid crashes.",
                    "severity": "HIGH",
                }


class StrictEthereumTxPaginationSqlRule(Rule):
    """
    Detects unsafe raw SQL used for Ethereum transaction pagination:
    - Using `IS` to compare non-null integer columns (e.g., `tx.transactionIndex IS $transactionIndex`).
    - Comparing `HEX(tx.hash)` to an interpolated `hashString` instead of a normalized raw hex (uppercase) value.

    Mirrors the fix that changed `IS` to `=` and used `fromTransaction.hash.toRawHexString().uppercase()`.
    """
    issue_type = "Unsafe Ethereum transaction pagination SQL"
    suggestion = (
        "Use `=` for integer comparisons (not `IS`) and compare HEX(tx.hash) to a normalized "
        "uppercase raw hex string (e.g., hash.toRawHexString().uppercase())."
    )

    KT_FILE_PATTERN = re.compile(r"\.kt$")
    # Note: keep simple kt file gate; raw SQL detection uses other patterns below
    TX_INDEX_IS_PATTERN = re.compile(r"tx\.transactionIndex\s+IS\s+\$?\w+")
    HEX_HASH_WITH_HASHSTRING_PATTERN = re.compile(r"HEX\(tx\.hash\)\s*[<=>]\s*\"\$\{[^}]*hashString[^}]*\}\"")
    HEX_HASH_DIRECT_HASHSTRING_PATTERN = re.compile(r"HEX\(tx\.hash\)\s*[<=>]\s*\$\{[^}]*hashString[^}]*\}")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        if not self.KT_FILE_PATTERN.search(file_path):
            return

        # Join for multi-line SQL detection
        content = "\n".join(lines)
        if not ("HEX(tx.hash)" in content or "transactionIndex" in content):
            return

        # Scan line by line for precise issues to report with accurate line numbers
        for i, raw in enumerate(lines):
            s = raw.strip()
            if not s:
                continue

            if self.TX_INDEX_IS_PATTERN.search(s):
                yield {
                    "line_num": i + 1,
                    "code": s,
                    "detail": "Use `=` instead of `IS` for integer comparison of tx.transactionIndex.",
                    "severity": "HIGH",
                }
            
            if self.HEX_HASH_WITH_HASHSTRING_PATTERN.search(s) or self.HEX_HASH_DIRECT_HASHSTRING_PATTERN.search(s):
                yield {
                    "line_num": i + 1,
                    "code": s,
                    "detail": "Compare HEX(tx.hash) against normalized uppercase raw hex, not `hashString`. Use toRawHexString().uppercase().",
                    "severity": "HIGH",
                }


class StrictEip20SupportBlockchainGuardRule(Rule):
    """
    Detects missing blockchain-type guard in EIP-20 support checks.

    Problem: supports(token) uses EIP-20 logic (casting to TokenType.Eip20 / building EvmAddress)
    without first ensuring that token.blockchainType is one of supported EVM chains, causing crashes
    on non-EVM networks like Tron (TRC20).

    Requires a guard like:
        if (!EvmBlockchainManager.blockchainTypes.contains(token.blockchainType)) return false
    before doing EIP-20-specific handling.
    """
    issue_type = "EIP-20 support check without EVM blockchain guard"
    suggestion = (
        "Add early return guard: if (!EvmBlockchainManager.blockchainTypes.contains(token.blockchainType)) return false, "
        "then proceed with EIP-20 address handling."
    )

    KT_FILE_PATTERN = re.compile(r"\.kt$")
    SUPPORTS_SIGNATURE = re.compile(r"fun\s+supports\s*\(\s*token\s*:\s*Token\s*\)\s*:\s*Boolean")
    EVM_GUARD_PATTERN = re.compile(r"EvmBlockchainManager\.blockchainTypes\.contains\s*\(\s*token\.blockchainType\s*\)")
    EIP20_CAST_PATTERN = re.compile(r"\(\s*token\.type\s+as\?\s*TokenType\.Eip20\s*\)")
    EVM_ADDRESS_PATTERN = re.compile(r"\bEvmAddress\s*\(")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        if not self.KT_FILE_PATTERN.search(file_path):
            return

        for i, raw in enumerate(lines):
            s = raw.strip()
            if not s or s.startswith("//"):
                continue

            if not self.SUPPORTS_SIGNATURE.search(s):
                continue

            # Inspect a limited window for guard and EIP-20 usage
            start = i
            end = min(len(lines), i + 60)
            window_lines = [x.strip() for x in lines[start:end]]
            window = "\n".join(window_lines)

            uses_eip20 = bool(self.EIP20_CAST_PATTERN.search(window)) or bool(self.EVM_ADDRESS_PATTERN.search(window))
            has_evm_guard = bool(self.EVM_GUARD_PATTERN.search(window))

            if uses_eip20 and not has_evm_guard:
                yield {
                    "line_num": i + 1,
                    "code": s,
                    "detail": "supports(token) handles EIP-20 without guarding non-EVM blockchains; add EvmBlockchainManager guard.",
                    "severity": "HIGH",
                }


class StrictHandledExceptionCatchRule(Rule):
    """
    Detects catching broad or transport-layer exceptions in higher layers instead of domain-level
    HandledException, which should be produced by a centralized handler (e.g., handleRecoverableException)
    and then caught at repositories/UI to avoid crashes and provide proper user resolutions.

    Flags:
      - catch(Exception)
      - catch(ClientRequestException) / catch(ServerResponseException)

    Recommends catching HandledException instead, and optionally checking ex.errorResolution
    before logging/handling.
    """
    issue_type = "Catching broad exceptions instead of HandledException"
    suggestion = (
        "Use a central mapping to HandledException and catch HandledException in repositories/UI. "
        "Avoid catching Exception/ClientRequestException/ServerResponseException directly."
    )

    KT_FILE_PATTERN = re.compile(r"\.kt$")
    CATCH_EXCEPTION = re.compile(r"catch\s*\(\s*(?:java\.lang\.)?Exception\b")
    CATCH_KTOR_CLIENT = re.compile(r"catch\s*\(\s*ClientRequestException\b")
    CATCH_KTOR_SERVER = re.compile(r"catch\s*\(\s*ServerResponseException\b")
    IMPORT_HANDLED = re.compile(r"import\s+ly\.david\.musicsearch\.shared\.domain\.error\.HandledException")
    CATCH_HANDLED = re.compile(r"catch\s*\(\s*HandledException\b")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        if not self.KT_FILE_PATTERN.search(file_path):
            return

        content = "\n".join(lines)
        has_handled_import = bool(self.IMPORT_HANDLED.search(content)) or "HandledException" in content

        for i, raw in enumerate(lines):
            s = raw.strip()
            if not s or s.startswith("//"):
                continue

            catches_broad = bool(self.CATCH_EXCEPTION.search(s)) or bool(self.CATCH_KTOR_CLIENT.search(s)) or bool(self.CATCH_KTOR_SERVER.search(s))
            if not catches_broad:
                continue

            # if the same window already catches HandledException, be lenient
            start = max(0, i - 6)
            end = min(len(lines), i + 8)
            window = "\n".join(x.strip() for x in lines[start:end])
            catches_handled = bool(self.CATCH_HANDLED.search(window))

            if not catches_handled:
                detail = "Replace broad/transport-layer catch with catch(HandledException) after mapping via central handler."
                severity = "HIGH" if has_handled_import else "MEDIUM"
                yield {
                    "line_num": i + 1,
                    "code": s,
                    "detail": detail,
                    "severity": severity,
                }


class StrictTmdbRatingNormalizationRule(Rule):
    """
    Detects unsafe submission of rating values taken directly from UI sliders/bars to TMDB endpoints
    without normalizing to allowed increments (e.g., integers). This can crash when old half-point
    ratings are re-submitted while the backend no longer accepts them.

    Flags patterns like:
      - val rating = ratingBar.value.toDouble()
      - val rating = binding.ratingSlider.value.toDouble()
      followed by passing `rating` to AddRating/AddEpisodeRating/addRating() without round()/floor()/ceil().

    Recommends applying kotlin.math.round(...) before submission and/or validating range [0,10].
    """
    issue_type = "Rating submitted without normalization to allowed increments"
    suggestion = (
        "Normalize rating before submission, e.g., val rating = round(slider.value.toDouble()); "
        "then submit. Also ensure rating in [0, 10]."
    )

    KT_FILE_PATTERN = re.compile(r"\.kt$")
    RATING_SOURCE_PATTERN = re.compile(r"\b(ratingBar|ratingSlider)\.value\.toDouble\s*\(\)")
    ROUND_USAGE_PATTERN = re.compile(r"\b(round|floor|ceil)\s*\(")
    ADD_RATING_CALL_PATTERN = re.compile(r"\bAdd(Rating|EpisodeRating)\s*\(.*\)\s*")
    INVOKE_ADDRATING_PATTERN = re.compile(r"\.addRating\s*\(\s*\)\s*")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        if not self.KT_FILE_PATTERN.search(file_path):
            return

        for i, raw in enumerate(lines):
            s = raw.strip()
            if not s or s.startswith("//"):
                continue

            # detect rating value acquisition
            if not self.RATING_SOURCE_PATTERN.search(s):
                continue

            # examine small window ahead for normalization and submission
            start = max(0, i - 2)
            end = min(len(lines), i + 12)
            window_lines = [x.strip() for x in lines[start:end]]
            window = "\n".join(window_lines)

            has_round = bool(self.ROUND_USAGE_PATTERN.search(window))
            has_submit = bool(self.ADD_RATING_CALL_PATTERN.search(window)) or bool(self.INVOKE_ADDRATING_PATTERN.search(window))

            if has_submit and not has_round:
                yield {
                    "line_num": i + 1,
                    "code": s,
                    "detail": "Rating value sourced from UI and submitted without round()/floor()/ceil() normalization.",
                    "severity": "HIGH",
                }


class StrictPlaybackReportNullGuardRule(Rule):
    """
    Detects missing null-guard before reporting playback progress when passing current stream info
    into reportProgress, which can cause NPE if stream info is null during track/subtitle switches.

    Mirrors fix: add `if (mCurrentStreamInfo == null) return;` before calling reportProgress(..., getCurrentStreamInfo(), ...).
    """
    issue_type = "Missing null-guard before reportProgress with stream info"
    suggestion = (
        "Add early return null-guard before reporting: `if (mCurrentStreamInfo == null) return;` "
        "or check `getCurrentStreamInfo() != null` prior to invoking reportProgress."
    )

    JAVA_FILE_PATTERN = re.compile(r"\.java$")
    REPORT_PROGRESS_PATTERN = re.compile(r"\breportProgress\s*\(")
    USES_STREAM_INFO_ARG_PATTERN = re.compile(r"\breportProgress\s*\(.*?(getCurrentStreamInfo\s*\(\)|mCurrentStreamInfo).*?\)")
    NULL_GUARD_MC_PATTERN = re.compile(r"if\s*\(\s*mCurrentStreamInfo\s*==\s*null\s*\)\s*return\s*;?")
    NULL_GUARD_GETTER_PATTERN = re.compile(r"if\s*\(\s*getCurrentStreamInfo\s*\(\)\s*==\s*null\s*\)\s*return\s*;?")
    POSITIVE_CHECK_PATTERN = re.compile(r"if\s*\(\s*(mCurrentStreamInfo|getCurrentStreamInfo\s*\(\))\s*!=\s*null\s*\)")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        if not self.JAVA_FILE_PATTERN.search(file_path):
            return

        for i, raw in enumerate(lines):
            s = raw.strip()
            if not s or s.startswith("//"):
                continue

            if not self.REPORT_PROGRESS_PATTERN.search(s):
                continue

            if not self.USES_STREAM_INFO_ARG_PATTERN.search(s):
                continue

            # look back for a nearby null-guard or positive check
            start = max(0, i - 8)
            end = i
            window = "\n".join(x.strip() for x in lines[start:end])
            has_guard = bool(self.NULL_GUARD_MC_PATTERN.search(window) or
                             self.NULL_GUARD_GETTER_PATTERN.search(window) or
                             self.POSITIVE_CHECK_PATTERN.search(window))

            if not has_guard:
                yield {
                    "line_num": i + 1,
                    "code": s,
                    "detail": "reportProgress is invoked with stream info but no preceding null-guard found.",
                    "severity": "HIGH",
                }


class StrictBottomSheetTargetStateRule(Rule):
    """
    Detects using BackportBottomSheetBehavior.state in visibility/flow control instead of
    getTargetState()/targetState while the sheet is settling, which can cause incorrect UI state
    decisions (e.g., hiding/unhiding logic) and crashes when removing last queue item.

    Flags conditions like:
      - if (playbackSheetBehavior.state == BackportBottomSheetBehavior.STATE_HIDDEN) { ... }
      - if (queueSheetBehavior.state != BackportBottomSheetBehavior.STATE_COLLAPSED) { ... }

    and recommends using targetState/getTargetState() for robust checks during STATE_SETTLING.
    """
    issue_type = "BottomSheet uses state instead of targetState during settling"
    suggestion = (
        "Use targetState (or getTargetState()) for conditional checks; state may be STATE_SETTLING and "
        "not reflect the intended target. Example: if (behavior.targetState == STATE_HIDDEN) { ... }."
    )

    KT_OR_JAVA = re.compile(r"\.(kt|java)$")
    STATE_COMPARE_PATTERN = re.compile(r"\.state\s*(==|!=)\s*BackportBottomSheetBehavior\.STATE_\w+")
    # Positive signal of using targetState; if present nearby, do not warn
    TARGETSTATE_PATTERN = re.compile(r"\b(getTargetState\s*\(\)|targetState)\b")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        if not self.KT_OR_JAVA.search(file_path):
            return

        for i, raw in enumerate(lines):
            s = raw.strip()
            if not s or s.startswith("//"):
                continue

            if not self.STATE_COMPARE_PATTERN.search(s):
                continue

            # If nearby window already uses targetState, be lenient
            start = max(0, i - 6)
            end = min(len(lines), i + 6)
            window = "\n".join(x.strip() for x in lines[start:end])
            if self.TARGETSTATE_PATTERN.search(window):
                continue

            yield {
                "line_num": i + 1,
                "code": s,
                "detail": "Use targetState/getTargetState() for checks; state can be STATE_SETTLING.",
                "severity": "HIGH",
            }


class StrictPlayerNullGuardRule(Rule):
    """
    Detects method calls on a Player-like field without null guards in reactive callbacks
    or async contexts, mirroring the NPE fix to check `if (player != null)` before invoking.
    """
    issue_type = "Nullable player method call without null guard"
    suggestion = "Guard player with null check before calling methods in async/reactive callbacks."

    # Heuristic: detect common player variable names and method calls
    PLAYER_CALL_PATTERN = re.compile(r"\b(player|videoPlayer|mediaPlayer)\.(set|play|pause|seek|setSponsorBlockMode|prepare|start|stop)\s*\(")
    NULL_GUARD_IF_PATTERN = re.compile(r"if\s*\(\s*(player|videoPlayer|mediaPlayer)\s*!?=\s*null\s*\)")
    OPTIONAL_GUARD_PATTERN = re.compile(r"\b(player|videoPlayer|mediaPlayer)\?\.")

    # Reactive/async context hints
    REACTIVE_CONTEXT_PATTERN = re.compile(r"(subscribe|onSuccess|onNext|Consumer|Single|Observable|Flow|launch|async)")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        if not (file_path.endswith('.java') or file_path.endswith('.kt')):
            return

        for i, raw in enumerate(lines):
            s = raw.strip()
            if not s or s.startswith("//"):
                continue

            m = self.PLAYER_CALL_PATTERN.search(s)
            if not m:
                continue

            var_name = m.group(1)
            # Look back/micro-window for guards
            window_start = max(0, i - 6)
            window_text = "\n".join(x.strip() for x in lines[window_start:i+1])
            has_if_guard = bool(self.NULL_GUARD_IF_PATTERN.search(window_text))
            has_safe_call = (f"{var_name}?." in window_text)
            in_reactive = bool(self.REACTIVE_CONTEXT_PATTERN.search(window_text))

            if not (has_if_guard or has_safe_call):
                severity = "HIGH" if in_reactive else "MEDIUM"
                yield {
                    "line_num": i + 1,
                    "code": s,
                    "detail": f"Call on '{var_name}' without null guard; add `if ({var_name} != null)` or safe call.",
                    "severity": severity,
                }

class StrictMediaPlaybackWakeLockPermissionRule(Rule):
    """
    Detects Android media playback foreground services without declaring WAKE_LOCK permission.

    Symptoms: Playback service starts and app may crash/stop when device sleeps due to missing
    power management permission. Fix is to add:
      <uses-permission android:name="android.permission.WAKE_LOCK" />

    Triggers if manifest indicates media playback foreground service (e.g.,
    foregroundServiceType="mediaPlayback" or uses FOREGROUND_SERVICE_MEDIA_PLAYBACK) or if a
    service likely to be a player is declared, but WAKE_LOCK permission is absent.
    """
    issue_type = "Missing WAKE_LOCK permission for media playback service"
    suggestion = (
        "Declare WAKE_LOCK permission in the module manifest: "
        "<uses-permission android:name=\"android.permission.WAKE_LOCK\" />."
    )

    MANIFEST_FILE_PATTERN = re.compile(r"AndroidManifest\.xml$")
    MEDIA_FGS_TYPE_PATTERN = re.compile(r"foregroundServiceType\s*=\s*\"[^\"]*mediaPlayback[^\"]*\"")
    USES_FGS_MEDIA_PERMISSION = re.compile(r"uses-permission[^>]+android\.permission\.FOREGROUND_SERVICE_MEDIA_PLAYBACK")
    SERVICE_NAME_HINTS = [
        re.compile(r"service[^>]+name=\"[^\"]*(Playback|Player|MediaBrowser|MediaSession)Service[^\"]*\"", re.I),
    ]
    WAKE_LOCK_PERMISSION_PATTERN = re.compile(r"uses-permission[^>]+android\.permission\.WAKE_LOCK")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        if not self.MANIFEST_FILE_PATTERN.search(file_path):
            return

        content = "\n".join(lines)

        has_media_fgs = bool(self.MEDIA_FGS_TYPE_PATTERN.search(content) or self.USES_FGS_MEDIA_PERMISSION.search(content))
        has_player_service = any(p.search(content) for p in self.SERVICE_NAME_HINTS)
        has_wake_lock = bool(self.WAKE_LOCK_PERMISSION_PATTERN.search(content))

        if (has_media_fgs or has_player_service) and not has_wake_lock:
            # Find a representative line (first <application> or top of file)
            line_num = 1
            for i, line in enumerate(lines):
                if "<application" in line:
                    line_num = i + 1
                    break
            yield {
                "line_num": line_num,
                "code": lines[line_num - 1].strip() if 0 < line_num <= len(lines) else "<manifest>",
                "detail": "Media playback foreground service without WAKE_LOCK permission.",
                "severity": "HIGH",
            }
class StrictBackupImportValidationRule(Rule):
    """
    Detects unsafe database backup import flows that can crash when a random file is selected:
    - Launching a file picker for import without restricting to .zip extension.
    - Extracting/processing a backup without validating expected entries (e.g., newpipe.db/newpipe.settings).

    Recommends: pass a file extension filter (e.g., EXTRA_FILTER_EXTENSION="zip") to the picker and
    validate the selected zip before extraction (e.g., isValidBackupFile(filePath)).
    """
    issue_type = "Unsafe backup import without file-type filter or zip validation"
    suggestion = (
        "Restrict picker to .zip and validate contents before extraction (check required entries)."
    )

    KT_OR_JAVA = re.compile(r"\.(kt|java)$")
    # Detect starting file picker for import
    STARTS_FILE_PICKER = re.compile(r"new\s+Intent\s*\(.*FilePickerActivityHelper\.class\)")
    EXTRA_FILTER_EXTENSION = re.compile(r"EXTRA_FILTER_EXTENSION\s*,\s*\"zip\"")
    START_ACTIVITY_FOR_RESULT = re.compile(r"startActivityForResult\s*\(|registerForActivityResult|launch\s*\(")

    # Detect import/extract methods and missing validation
    IMPORT_METHOD_HINT = re.compile(r"import(Database|Data|Backup)")
    ZIP_EXTRACT_CALL = re.compile(r"(extract(Db|Database)|ZipHelper\.extractFileFromZip|ZipFile\s*\()")
    VALIDATION_CALL = re.compile(r"isValidBackupFile\s*\(")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        if not self.KT_OR_JAVA.search(file_path):
            return

        content = "\n".join(lines)

        # Case 1: File picker launched without zip filter
        if self.STARTS_FILE_PICKER.search(content) and self.START_ACTIVITY_FOR_RESULT.search(content):
            # find each intent creation line and check nearby for EXTRA_FILTER_EXTENSION
            for i, raw in enumerate(lines):
                s = raw.strip()
                if self.STARTS_FILE_PICKER.search(s):
                    start = i
                    end = min(len(lines), i + 12)
                    window = "\n".join(x.strip() for x in lines[start:end])
                    if not self.EXTRA_FILTER_EXTENSION.search(window):
                        yield {
                            "line_num": i + 1,
                            "code": s,
                            "detail": "File picker for import lacks .zip filter (EXTRA_FILTER_EXTENSION=\"zip\").",
                            "severity": "MEDIUM",
                        }

        # Case 2: Import/extract without prior validation
        for i, raw in enumerate(lines):
            s = raw.strip()
            if not s:
                continue
            if self.IMPORT_METHOD_HINT.search(s):
                # scan method body window for extract without isValidBackupFile
                start = i
                end = min(len(lines), i + 120)
                window = "\n".join(x.strip() for x in lines[start:end])
                uses_extract = bool(self.ZIP_EXTRACT_CALL.search(window))
                has_validation = bool(self.VALIDATION_CALL.search(window))
                if uses_extract and not has_validation:
                    yield {
                        "line_num": i + 1,
                        "code": s,
                        "detail": "Backup extraction performed without validating zip structure (e.g., newpipe.db/settings).",
                        "severity": "HIGH",
                    }


class StrictGroupieStartDragViewHolderRule(Rule):
    """
    Detects incorrect startDrag usage in Groupie items where a new ViewHolder is constructed from
    a binding inside bind(viewBinding, position) and passed to dragCallback.startDrag(...).

    This can crash when reordering because the drag must be started with the actual holder instance
    provided by the adapter. Recommended fix: move touch listener to
    bind(viewHolder, position, payloads) and call startDrag(viewHolder) directly.
    """
    issue_type = "Groupie drag uses new ViewHolder instead of provided holder"
    suggestion = (
        "Implement bind(viewHolder, position, payloads) and set listener there; call startDrag(viewHolder) "
        "instead of constructing GroupieViewHolder(binding)."
    )

    KT_FILE_PATTERN = re.compile(r"\.kt$")
    BIND_BINDING_SIG = re.compile(r"fun\s+bind\s*\(\s*viewBinding\s*:\s*[A-Za-z0-9_<>.]+\s*,\s*position\s*:\s*Int\s*\)")
    TOUCH_SETTER_PATTERN = re.compile(r"\.setOnTouchListener\s*\(")
    NEW_GROUPIE_VH_FROM_BINDING = re.compile(r"GroupieViewHolder\s*\(\s*viewBinding\s*\)")
    START_DRAG_CALL = re.compile(r"dragCallback\.startDrag\s*\(")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        if not self.KT_FILE_PATTERN.search(file_path):
            return

        for i, raw in enumerate(lines):
            s = raw.strip()
            if not s:
                continue

            if not self.BIND_BINDING_SIG.search(s):
                continue

            # Inspect method body window for listener and incorrect holder creation
            start = i
            end = min(len(lines), i + 60)
            window = "\n".join(x.strip() for x in lines[start:end])

            if self.TOUCH_SETTER_PATTERN.search(window) and self.START_DRAG_CALL.search(window) and self.NEW_GROUPIE_VH_FROM_BINDING.search(window):
                yield {
                    "line_num": i + 1,
                    "code": s,
                    "detail": "Use existing viewHolder in bind(viewHolder, position, payloads) for startDrag; do not construct GroupieViewHolder(viewBinding).",
                    "severity": "HIGH",
                }


class StrictRxSubscribeErrorHandlerRule(Rule):
    """
    Detects RxJava subscribe() calls without an explicit onError handler, which can cause
    OnErrorNotImplementedException and crash on startup interactions (e.g., opening videos
    before views/bindings are ready).

    Flags:
      - .subscribe(<onNext>) single-argument subscribe
      - subscribe with only onNext and missing onError within a small window

    Recommends providing an onError consumer and handling UI-safe fallbacks.
    """
    issue_type = "Rx subscribe without onError handler (OnErrorNotImplemented risk)"
    suggestion = (
        "Use subscribe(onNext, onError) and handle errors (e.g., showSnackBarError / fallback)."
    )

    KT_OR_JAVA = re.compile(r"\.(kt|java)$")
    SUBSCRIBE_CALL = re.compile(r"\.subscribe\s*\(")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        if not self.KT_OR_JAVA.search(file_path):
            return

        i = 0
        while i < len(lines):
            line = lines[i]
            if self.SUBSCRIBE_CALL.search(line):
                # accumulate until a closing parenthesis then optional semicolon/paren end
                buf = line.strip()
                j = i + 1
                max_look = min(len(lines), i + 15)
                while j < max_look and buf.count("(") > buf.count(")"):
                    buf += "\n" + lines[j].strip()
                    j += 1
                # Remove nested parentheses inside strings is hard; heuristic: check for comma at top-level
                # Simple heuristic: after 'subscribe(', ensure there's a comma before final ')'
                try:
                    inner = buf.split("subscribe", 1)[1]
                    inner = inner[inner.find("(") + 1: inner.rfind(")")]
                except Exception:
                    inner = ""
                has_comma = "," in inner
                # also treat presence of 'throwable' arrow or second lambda as a sign of onError
                has_error_lambda_hint = "throwable ->" in inner or "it ->" in inner and "," in inner

                if not has_comma and not has_error_lambda_hint:
                    yield {
                        "line_num": i + 1,
                        "code": lines[i].strip(),
                        "detail": "subscribe() missing onError handler; add subscribe(onNext, onError).",
                        "severity": "HIGH",
                    }
                i = j
                continue
            i += 1


class StrictPaidContentExceptionRule(Rule):
    """
    Detects Bandcamp extractors signaling paywalled content with generic exceptions instead of
    PaidContentException, which prevents upper layers from rendering proper UI and can surface as
    confusing crashes.

    Flags in Bandcamp extractor sources:
      - Missing track info handled via ContentNotAvailableException
      - Null file in trackinfo handled via ExtractionException

    Recommends throwing PaidContentException in these cases.
    """
    issue_type = "Paywalled content should throw PaidContentException (Bandcamp)"
    suggestion = (
        "In Bandcamp extractors, throw PaidContentException when album/track is paywalled (e.g., "
        "trackInfo.isEmpty() or trackinfo[0].file is null)."
    )

    JAVA_FILE_PATTERN = re.compile(r"\.java$")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        if not (self.JAVA_FILE_PATTERN.search(file_path) and "bandcamp" in file_path.lower()):
            return

        content = "\n".join(lines)

        # Heuristics for problematic patterns
        has_trackinfo_empty = re.search(r"track ?info|trackInfo", content, re.I) and re.search(r"isEmpty\s*\(\)", content)
        throws_content_not_available = "new ContentNotAvailableException" in content
        has_file_null_check = re.search(r"isNull\s*\(\s*\"file\"\s*\)\s*", content)
        throws_extraction_exception = "new ExtractionException" in content

        if has_trackinfo_empty and throws_content_not_available:
            # report first offending throw line
            for i, l in enumerate(lines):
                if "new ContentNotAvailableException" in l:
                    yield {
                        "line_num": i + 1,
                        "code": l.strip(),
                        "detail": "Album requires purchase; throw PaidContentException instead of ContentNotAvailableException.",
                        "severity": "HIGH",
                    }
                    break

        if has_file_null_check and throws_extraction_exception:
            for i, l in enumerate(lines):
                if "new ExtractionException" in l:
                    yield {
                        "line_num": i + 1,
                        "code": l.strip(),
                        "detail": "Track file is null (paywalled); throw PaidContentException instead of ExtractionException.",
                        "severity": "HIGH",
                    }
                    break

            
class StrictMediaServiceForegroundStartRule(Rule):
    """
    Detects Android media playback services that don't immediately start foreground notifications
    in onCreate/onStartCommand, which can crash on Android 8+ if the service never enters
    foreground while doing heavy initialization.

    Flags service classes (e.g., PlayerService) where:
      - onCreate or onStartCommand is present, AND
      - neither startForeground(...) nor createNotificationAndStartForeground(...) is invoked
        within the respective method body.
    """
    issue_type = "Media service does not start foreground notification early"
    suggestion = (
        "In onCreate/onStartCommand, call notificationUtil.createNotificationAndStartForeground() "
        "(or startForeground) before heavy work to avoid crashes on Android 8+."
    )

    JAVA_FILE_PATTERN = re.compile(r"\.java$")
    CLASS_SERVICE_PATTERN = re.compile(r"class\s+\w+Service\b.*extends\s+\w*Service")
    METHOD_ONCREATE = re.compile(r"void\s+onCreate\s*\(\s*\)")
    METHOD_ONSTART = re.compile(r"int\s+onStartCommand\s*\(")
    CALL_STARTFG = re.compile(r"startForeground\s*\(")
    CALL_CREATE_NOTIFICATION = re.compile(r"createNotificationAndStartForeground\s*\(")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        if not self.JAVA_FILE_PATTERN.search(file_path):
            return

        content = "\n".join(lines)
        if not self.CLASS_SERVICE_PATTERN.search(content):
            return

        # scan for onCreate, ensure calls present in its body
        for i, raw in enumerate(lines):
            s = raw.strip()
            if self.METHOD_ONCREATE.search(s):
                body = self._collect_method_body(lines, i)
                if body is not None and not (self.CALL_STARTFG.search(body) or self.CALL_CREATE_NOTIFICATION.search(body)):
                    yield {
                        "line_num": i + 1,
                        "code": s,
                        "detail": "onCreate does not start foreground notification.",
                        "severity": "HIGH",
                    }
            if self.METHOD_ONSTART.search(s):
                body = self._collect_method_body(lines, i)
                if body is not None and not (self.CALL_STARTFG.search(body) or self.CALL_CREATE_NOTIFICATION.search(body)):
                    yield {
                        "line_num": i + 1,
                        "code": s,
                        "detail": "onStartCommand does not start foreground notification.",
                        "severity": "HIGH",
                    }

    def _collect_method_body(self, lines: List[str], start_idx: int) -> str:
        buf = []
        brace = 0
        started = False
        for j in range(start_idx, min(len(lines), start_idx + 300)):
            line = lines[j]
            if '{' in line:
                brace += line.count('{')
                started = True
            if '}' in line and started:
                brace -= line.count('}')
                buf.append(line)
                if brace <= 0:
                    return "\n".join(x.strip() for x in buf)
            else:
                buf.append(line)
        return "\n".join(x.strip() for x in buf)


class StrictNullGuardBeforePlayerUsageRule(Rule):
    """
    Detects usage of player reference in service methods without prior null-check, leading to NPE
    when the service is starting/stopping quickly (e.g., user closes mini player before load).

    Flags lines like:
      - player.handleIntent(...)
      - player.UIs().get(...)
      - player.getPlayQueue() / player.videoPlayerSelected() / player.exoPlayerIsNull()
    without a nearby `if (player != null)` guard in the method.
    """
    issue_type = "Player used without null-guard in service methods"
    suggestion = "Guard player usage with `if (player != null) { ... }` to avoid NPE during startup/shutdown."

    JAVA_FILE_PATTERN = re.compile(r"\.java$")
    PLAYER_USE_PATTERN = re.compile(r"player\.(handleIntent|UIs\s*\(\)|getPlayQueue|videoPlayerSelected|exoPlayerIsNull)")
    NULL_GUARD_PATTERN = re.compile(r"if\s*\(\s*player\s*!=\s*null\s*\)")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        if not self.JAVA_FILE_PATTERN.search(file_path):
            return

        for i, raw in enumerate(lines):
            s = raw.strip()
            if not s:
                continue
            if self.PLAYER_USE_PATTERN.search(s):
                # look back a few lines for null guard
                start = max(0, i - 6)
                window = "\n".join(x.strip() for x in lines[start:i+1])
                if not self.NULL_GUARD_PATTERN.search(window):
                    yield {
                        "line_num": i + 1,
                        "code": s,
                        "detail": "player used without prior null-guard in nearby lines.",
                        "severity": "HIGH",
                    }


class IncompleteBooleanConditionRule(Rule):
    """
    Detects incomplete boolean conditions in ternary operators that can cause logical errors.
    This rule specifically targets the pattern shown in the PR where boolean variables
    are checked for null but not for their actual boolean value, leading to incorrect logic.
    """
    issue_type = "Incomplete Boolean Condition in Ternary Operator"
    suggestion = "Boolean conditions should check both null and boolean value. Replace incomplete conditions with proper boolean logic using && and || operators."
    
    # Pattern to match the specific problematic pattern from the PR
    # Matches: var != null && (...) ? var : false
    PROBLEMATIC_PATTERN = re.compile(
        r"(\w+)\s*!=\s*null\s*&&\s*\([^)]+\)\s*\?\s*\1\s*:\s*false"
    )
    
    # Pattern to match boolean variable declarations
    BOOLEAN_VAR_PATTERN = re.compile(r"(boolean|Boolean)\s+(\w+)")
    
    # Common boolean variable names that might be used in this pattern
    BOOLEAN_VAR_NAMES = [
        'backFromChooseProductPage', 'isVisible', 'isEnabled', 'isActive',
        'hasData', 'isValid', 'isReady', 'isLoaded', 'isInitialized',
        'isScannerVisible', 'isProductWillBeFilled'
    ]
    
    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        # Only analyze Java files (the PR shows Java code)
        if not file_path.endswith('.java'):
            return
        
        boolean_vars = set()
        
        # First pass: collect boolean variable names
        for line in lines:
            boolean_match = self.BOOLEAN_VAR_PATTERN.search(line)
            if boolean_match:
                var_name = boolean_match.group(2)
                boolean_vars.add(var_name)
        
        # Add common boolean variable names
        boolean_vars.update(self.BOOLEAN_VAR_NAMES)
        
        # Second pass: check for problematic ternary patterns
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped_line = line.strip()
            
            if not stripped_line or stripped_line.startswith("//"):
                continue
            
            # Check for the specific problematic pattern
            for var_name in boolean_vars:
                # More flexible pattern that matches the exact issue from the PR
                pattern = rf"{re.escape(var_name)}\s*!=\s*null\s*&&\s*\([^)]+\)\s*\?\s*{re.escape(var_name)}\s*:\s*false"
                if re.search(pattern, stripped_line):
                    yield {
                        "line_num": line_num,
                        "code": line.strip(),
                        "detail": f"Incomplete boolean condition detected: `{var_name} != null && (...) ? {var_name} : false`. This pattern should check both null and boolean value: `{var_name} != null && {var_name} && (...)`.",
                        "severity": "HIGH"
                    }
                    break
            
            # Also check for the general pattern with any variable name
            ternary_match = self.PROBLEMATIC_PATTERN.search(stripped_line)
            if ternary_match:
                var_name = ternary_match.group(1)
                # Only report if it's a known boolean variable or follows the pattern
                if var_name in boolean_vars or self._looks_like_boolean_var(var_name):
                    yield {
                        "line_num": line_num,
                        "code": line.strip(),
                        "detail": f"Incomplete boolean condition detected: `{var_name} != null && (...) ? {var_name} : false`. This pattern should check both null and boolean value: `{var_name} != null && {var_name} && (...)`.",
                        "severity": "HIGH"
                    }
    
    def _looks_like_boolean_var(self, var_name: str) -> bool:
        """Check if a variable name looks like it could be a boolean variable."""
        boolean_prefixes = ['is', 'has', 'can', 'should', 'will', 'back', 'from']
        boolean_suffixes = ['Enabled', 'Visible', 'Active', 'Valid', 'Ready', 'Loaded']
        
        # Check if it starts with a boolean prefix
        for prefix in boolean_prefixes:
            if var_name.startswith(prefix):
                return True
        
        # Check if it ends with a boolean suffix
        for suffix in boolean_suffixes:
            if var_name.endswith(suffix):
                return True
        
        # Check if it contains common boolean words
        boolean_words = ['page', 'choose', 'product', 'scanner', 'visible']
        for word in boolean_words:
            if word in var_name.lower():
                return True
        
        return False


class StrictPhotoViewScaleBoundsRule(Rule):
    """
    Detects unsafe calls to PhotoView/PhotoViewAttacher setScale using a saved zoom value
    (e.g., from savedInstanceState) without clamping within [minScale, maxScale].

    This rules targets crashes like IllegalArgumentException("Scale must be within the range of minScale and maxScale").
    """
    issue_type = "PhotoView setScale without min/max bounds validation"
    suggestion = (
        "Clamp saved zoom before calling setScale: saved = savedInstanceState.getFloat(...); "
        "float min = image.getMinimumScale(); float max = image.getMaximumScale(); "
        "saved = Math.min(max, Math.max(min, saved)); then image.setScale(saved); optionally wrap with try/catch."
    )

    JAVA_FILE_PATTERN = re.compile(r"\.(java|kt)$")

    SETSCALE_CALL_PATTERN = re.compile(r"\b(setScale)\s*\(\s*([^\)]+)\)")
    GET_SAVED_FLOAT_PATTERN = re.compile(r"\b(getFloat|getSerializable|getDouble)\s*\(")
    MIN_REF_PATTERN = re.compile(r"getMinimumScale\s*\(")
    MAX_REF_PATTERN = re.compile(r"getMaximumScale\s*\(")
    CLAMP_PATTERN = re.compile(r"Math\.(min|max)\s*\(|kotlin\.math\.(min|max)\s*\(")
    TRYCATCH_IAE_PATTERN = re.compile(r"catch\s*\(\s*IllegalArgumentException\s*")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        if not self.JAVA_FILE_PATTERN.search(file_path):
            return

        for i, raw in enumerate(lines):
            s = raw.strip()
            if not s or s.startswith("//"):
                continue

            m = self.SETSCALE_CALL_PATTERN.search(s)
            if not m:
                continue

            arg_expr = m.group(2)
            # Look back a small window to see how arg_expr is derived
            window_start = max(0, i - 12)
            window_end = min(len(lines), i + 1)
            window = "\n".join(x.strip() for x in lines[window_start:window_end])

            # Heuristic: consider risky if argument is directly from savedInstanceState/getFloat or variable sourced from it
            risky_source = bool(self.GET_SAVED_FLOAT_PATTERN.search(window))

            # Check presence of min/max references or explicit clamp around the argument or nearby.
            has_min = bool(self.MIN_REF_PATTERN.search(window))
            has_max = bool(self.MAX_REF_PATTERN.search(window))
            has_clamp = bool(self.CLAMP_PATTERN.search(window))

            # Check try/catch for IllegalArgumentException nearby
            has_try_catch = bool(self.TRYCATCH_IAE_PATTERN.search(window))

            if risky_source and not ((has_min and has_max and has_clamp)):
                severity = "HIGH" if not has_try_catch else "MEDIUM"
                yield {
                    "line_num": i + 1,
                    "code": s,
                    "detail": "setScale uses saved zoom without clamping within [min,max]; add clamp and optionally try/catch.",
                    "severity": severity,
                }


class StrictEmptyRecipientHeadersRule(Rule):
    """
    Detects unsafe calls to RecipientLayoutCreator.createRecipientLayout() without checking
    if numberOfRecipients is zero, which can cause IllegalArgumentException: Failed requirement.

    This rule specifically targets the pattern shown in the GitHub issue #6621 where
    RecipientNamesView.onLayout() calls createRecipientLayout() without validating that
    there are recipients to display, causing crashes when messages have empty recipient headers.
    """
    issue_type = "Unsafe RecipientLayoutCreator Call Without Empty Check"
    suggestion = "Check if numberOfRecipients == 0 before calling createRecipientLayout() to prevent IllegalArgumentException. Add early return when there are no recipients to display."
    
    # Pattern to match createRecipientLayout calls
    CREATE_RECIPIENT_LAYOUT_PATTERN = re.compile(r"(\w+\.)?createRecipientLayout\s*\(")
    
    # Pattern to match onLayout method (where the issue occurs)
    ON_LAYOUT_PATTERN = re.compile(r"(override\s+)?fun\s+onLayout\s*\(")
    
    # Pattern to match numberOfRecipients variable usage
    NUMBER_OF_RECIPIENTS_PATTERN = re.compile(r"numberOfRecipients")
    
    # Pattern to match zero comparison checks
    ZERO_CHECK_PATTERN = re.compile(r"(numberOfRecipients\s*==\s*0|numberOfRecipients\s*>\s*0|numberOfRecipients\s*!=\s*0)")
    
    # Pattern to match early return statements
    EARLY_RETURN_PATTERN = re.compile(r"return\s*;")
    
    # Pattern to match if statements with zero checks
    IF_ZERO_CHECK_PATTERN = re.compile(r"if\s*\(\s*numberOfRecipients\s*==\s*0\s*\)")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        # Only analyze Kotlin files (based on the issue being in .kt files)
        if not file_path.endswith('.kt'):
            return
            
        in_on_layout = False
        on_layout_start = 0
        has_zero_check = False
        has_early_return = False
        
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped_line = line.strip()
            
            if not stripped_line or stripped_line.startswith("//"):
                continue
            
            # Check if we're entering onLayout method
            if self.ON_LAYOUT_PATTERN.search(stripped_line):
                in_on_layout = True
                on_layout_start = i
                has_zero_check = False
                has_early_return = False
                continue
            
            # Check if we're exiting the onLayout method (closing brace at same indentation level)
            if in_on_layout and stripped_line == "}" and i > on_layout_start:
                # Check if this is the end of the onLayout method by looking at indentation
                if i > 0 and len(lines[i-1].strip()) > 0:
                    prev_indent = len(lines[i-1]) - len(lines[i-1].lstrip())
                    curr_indent = len(line) - len(line.lstrip())
                    if curr_indent <= prev_indent:
                        in_on_layout = False
                        continue
            
            # If we're in onLayout method, check for createRecipientLayout calls
            if in_on_layout and self.CREATE_RECIPIENT_LAYOUT_PATTERN.search(stripped_line):
                # Look for zero checks in the method
                method_lines = lines[on_layout_start:i+1]
                method_text = "\n".join(method_lines)
                
                # Check if there's a zero check before this call
                has_zero_check = bool(self.ZERO_CHECK_PATTERN.search(method_text))
                has_early_return = bool(self.EARLY_RETURN_PATTERN.search(method_text))
                
                # If no zero check found, this is a potential issue
                if not has_zero_check:
                    severity = "HIGH"
                    detail = "createRecipientLayout() called without checking if numberOfRecipients == 0. This can cause IllegalArgumentException when messages have empty recipient headers."
                    
                    yield {
                        "line_num": line_num,
                        "code": stripped_line,
                        "detail": detail,
                        "severity": severity
                    }
                elif has_zero_check and not has_early_return:
                    # Has zero check but no early return - medium severity
                    severity = "MEDIUM"
                    detail = "createRecipientLayout() called with zero check but no early return. Consider adding early return when numberOfRecipients == 0 for better performance."
                    
                    yield {
                        "line_num": line_num,
                        "code": stripped_line,
                        "detail": detail,
                        "severity": severity
                    }
class StrictSwipeCallbackNullCheckRule(Rule):
    """
    Detects unsafe access to ViewHolder properties in SwipeCallback methods without null checks,
    which can cause IllegalStateException when items are removed during swipe operations.

    This rule specifically targets the pattern shown in GitHub issue #6609 where
    MessageListSwipeCallback methods directly access viewHolder.messageListItem without
    checking if the item still exists, causing crashes when messages are deleted during swipe.
    """
    issue_type = "Unsafe SwipeCallback ViewHolder Access Without Null Check"
    suggestion = "Add null checks when accessing ViewHolder properties in SwipeCallback methods. Use 'val item = viewHolder.property ?: return' pattern to prevent IllegalStateException when items are removed during swipe operations."
    
    # Pattern to match SwipeCallback method signatures
    SWIPE_CALLBACK_METHOD_PATTERN = re.compile(r"(override\s+)?fun\s+(onSwipeStarted|onSwipeDirectionChanged|onSwiped|onSwipeEnded|clearView)\s*\(")
    
    # Pattern to match ViewHolder property access
    VIEWHOLDER_PROPERTY_ACCESS_PATTERN = re.compile(r"viewHolder\.(\w+)(?!\s*\?)")
    
    # Pattern to match safe null checks with early return
    SAFE_NULL_CHECK_PATTERN = re.compile(r"val\s+\w+\s*=\s*viewHolder\.\w+\s*\?\:\s*return")
    
    # Pattern to match direct property access without null check
    UNSAFE_PROPERTY_ACCESS_PATTERN = re.compile(r"viewHolder\.(\w+)(?!\s*\?)")
    
    # Pattern to match method calls on ViewHolder properties
    METHOD_CALL_ON_PROPERTY_PATTERN = re.compile(r"viewHolder\.(\w+)\.(\w+)\s*\(")
    
    # Common ViewHolder property names that should be null-checked
    RISKY_PROPERTIES = ['messageListItem', 'item', 'data', 'entity', 'model']

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        # Only analyze Kotlin files
        if not file_path.endswith('.kt'):
            return
            
        in_swipe_callback_method = False
        method_start = 0
        has_safe_null_check = False
        
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped_line = line.strip()
            
            if not stripped_line or stripped_line.startswith("//"):
                continue
            
            # Check if we're entering a SwipeCallback method
            if self.SWIPE_CALLBACK_METHOD_PATTERN.search(stripped_line):
                in_swipe_callback_method = True
                method_start = i
                has_safe_null_check = False
                continue
            
            # Check if we're exiting the method (closing brace at same or lower indentation)
            if in_swipe_callback_method and stripped_line == "}" and i > method_start:
                if i > 0 and len(lines[i-1].strip()) > 0:
                    prev_indent = len(lines[i-1]) - len(lines[i-1].lstrip())
                    curr_indent = len(line) - len(line.lstrip())
                    if curr_indent <= prev_indent:
                        in_swipe_callback_method = False
                        continue
            
            # If we're in a SwipeCallback method, check for unsafe property access
            if in_swipe_callback_method:
                # Check for safe null check pattern
                if self.SAFE_NULL_CHECK_PATTERN.search(stripped_line):
                    has_safe_null_check = True
                    continue
                
                # Check for unsafe ViewHolder property access
                unsafe_access = self.UNSAFE_PROPERTY_ACCESS_PATTERN.search(stripped_line)
                if unsafe_access:
                    property_name = unsafe_access.group(1)
                    
                    # Check if this is a risky property that should be null-checked
                    if property_name in self.RISKY_PROPERTIES or 'Item' in property_name or 'Data' in property_name:
                        # Look for any null check in the method
                        method_lines = lines[method_start:i+1]
                        method_text = "\n".join(method_lines)
                        
                        # Check if there's a safe null check for this property
                        property_null_check = re.compile(rf"val\s+\w+\s*=\s*viewHolder\.{property_name}\s*\?\:\s*return")
                        has_property_null_check = bool(property_null_check.search(method_text))
                        
                        if not has_property_null_check:
                            severity = "HIGH"
                            detail = f"Unsafe access to viewHolder.{property_name} without null check in SwipeCallback method. This can cause IllegalStateException when items are removed during swipe operations."
                            
                            yield {
                                "line_num": line_num,
                                "code": stripped_line,
                                "detail": detail,
                                "severity": severity
                            }
                
                # Check for method calls on ViewHolder properties
                method_call = self.METHOD_CALL_ON_PROPERTY_PATTERN.search(stripped_line)
                if method_call:
                    property_name = method_call.group(1)
                    method_name = method_call.group(2)
                    
                    if property_name in self.RISKY_PROPERTIES or 'Item' in property_name or 'Data' in property_name:
                        # Look for null check in the method
                        method_lines = lines[method_start:i+1]
                        method_text = "\n".join(method_lines)
                        
                        # Check if there's a safe null check for this property
                        property_null_check = re.compile(rf"val\s+\w+\s*=\s*viewHolder\.{property_name}\s*\?\:\s*return")
                        has_property_null_check = bool(property_null_check.search(method_text))
                        
                        if not has_property_null_check:
                            severity = "HIGH"
                            detail = f"Method call on viewHolder.{property_name}.{method_name} without null check in SwipeCallback method. This can cause IllegalStateException when items are removed during swipe operations."
                            
                            yield {
                                "line_num": line_num,
                                "code": stripped_line,
                                "detail": detail,
                                "severity": severity
                            }


class StrictWorkerFactoryNullSafetyRule(Rule):
    """
    Detects unsafe WorkerFactory implementations that can cause crashes when dependency injection fails.
    
    This rule specifically targets the pattern shown in GitHub issue #6558 where
    K9WorkerFactory.createWorker() uses getKoin().get() which throws exceptions when
    dependencies are not available, causing app crashes. The fix uses getOrNull() and
    returns nullable ListenableWorker.
    """
    issue_type = "Unsafe WorkerFactory Dependency Injection Without Null Safety"
    suggestion = "Use getOrNull() instead of get() in WorkerFactory.createWorker() and return nullable ListenableWorker? to prevent crashes when dependencies are not available."
    
    # Pattern to match WorkerFactory class definitions
    WORKER_FACTORY_PATTERN = re.compile(r"class\s+(\w*WorkerFactory\w*)\s*.*WorkerFactory")
    
    # Pattern to match createWorker method
    CREATE_WORKER_PATTERN = re.compile(r"(override\s+)?fun\s+createWorker\s*\(")
    
    # Pattern to match unsafe get() calls
    UNSAFE_GET_PATTERN = re.compile(r"\.get\s*\(\s*(\w+)\s*\)")
    
    # Pattern to match safe getOrNull() calls
    SAFE_GET_OR_NULL_PATTERN = re.compile(r"\.getOrNull\s*\(\s*(\w+)\s*\)")
    
    # Pattern to match return type declarations
    RETURN_TYPE_PATTERN = re.compile(r"\)\s*:\s*(ListenableWorker\??)")
    
    # Pattern to match Koin dependency injection
    KOIN_GET_PATTERN = re.compile(r"getKoin\(\)\.get\s*\(")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        # Only analyze Kotlin files
        if not file_path.endswith('.kt'):
            return
            
        in_worker_factory = False
        in_create_worker = False
        method_start = 0
        has_safe_get = False
        has_nullable_return = False
        
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped_line = line.strip()
            
            if not stripped_line or stripped_line.startswith("//"):
                continue
            
            # Check if we're in a WorkerFactory class
            if self.WORKER_FACTORY_PATTERN.search(stripped_line):
                in_worker_factory = True
                continue
            
            # Check if we're entering createWorker method
            if in_worker_factory and self.CREATE_WORKER_PATTERN.search(stripped_line):
                in_create_worker = True
                method_start = i
                has_safe_get = False
                has_nullable_return = False
                
                # Check return type
                return_type_match = self.RETURN_TYPE_PATTERN.search(stripped_line)
                if return_type_match:
                    return_type = return_type_match.group(1)
                    has_nullable_return = return_type.endswith('?')
                continue
            
            # Check if we're exiting the createWorker method
            if in_create_worker and stripped_line == "}" and i > method_start:
                if i > 0 and len(lines[i-1].strip()) > 0:
                    prev_indent = len(lines[i-1]) - len(lines[i-1].lstrip())
                    curr_indent = len(line) - len(line.lstrip())
                    if curr_indent <= prev_indent:
                        in_create_worker = False
                        continue
            
            # If we're in createWorker method, check for unsafe patterns
            if in_create_worker:
                # Check for safe getOrNull usage
                if self.SAFE_GET_OR_NULL_PATTERN.search(stripped_line):
                    has_safe_get = True
                    continue
                
                # Check for unsafe get() calls
                unsafe_get = self.UNSAFE_GET_PATTERN.search(stripped_line)
                if unsafe_get and not has_safe_get:
                    # Check if this is a Koin get() call
                    if self.KOIN_GET_PATTERN.search(stripped_line):
                        severity = "HIGH"
                        detail = "Unsafe getKoin().get() call in WorkerFactory.createWorker() can cause crashes when dependencies are not available. Use getOrNull() instead."
                        
                        yield {
                            "line_num": line_num,
                            "code": stripped_line,
                            "detail": detail,
                            "severity": severity
                        }
                
                # Check for non-nullable return type
                if not has_nullable_return and "return" in stripped_line:
                    severity = "MEDIUM"
                    detail = "WorkerFactory.createWorker() should return ListenableWorker? (nullable) to handle cases where dependency injection fails."
                    
                    yield {
                        "line_num": line_num,
                        "code": stripped_line,
                        "detail": detail,
                        "severity": severity
                    }


class StrictKoinDependencyInjectionRule(Rule):
    """
    Detects unsafe Koin dependency injection patterns that can cause crashes.
    
    This rule specifically targets patterns where getKoin().get() is used without
    proper null safety, which can throw exceptions when dependencies are not available.
    The safer approach is to use getOrNull() or handle exceptions properly.
    """
    issue_type = "Unsafe Koin Dependency Injection Without Exception Handling"
    suggestion = "Use getOrNull() instead of get() for Koin dependency injection, or wrap get() calls in try-catch blocks to handle NoBeanDefFoundException gracefully."
    
    # Pattern to match unsafe Koin get() calls
    KOIN_UNSAFE_GET_PATTERN = re.compile(r"getKoin\(\)\.get\s*\(")
    
    # Pattern to match safe Koin getOrNull() calls
    KOIN_SAFE_GET_OR_NULL_PATTERN = re.compile(r"getKoin\(\)\.getOrNull\s*\(")
    
    # Pattern to match try-catch blocks
    TRY_CATCH_PATTERN = re.compile(r"try\s*\{")
    
    # Pattern to match NoBeanDefFoundException handling
    NO_BEAN_DEF_EXCEPTION_PATTERN = re.compile(r"catch\s*\([^)]*NoBeanDefFoundException[^)]*\)")
    
    # Contexts where Koin injection is commonly used
    RISKY_CONTEXTS = ['WorkerFactory', 'Service', 'Repository', 'ViewModel', 'Fragment', 'Activity']

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        # Only analyze Kotlin files
        if not file_path.endswith('.kt'):
            return
            
        in_try_block = False
        has_exception_handling = False
        
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped_line = line.strip()
            
            if not stripped_line or stripped_line.startswith("//"):
                continue
            
            # Track try-catch blocks
            if self.TRY_CATCH_PATTERN.search(stripped_line):
                in_try_block = True
                has_exception_handling = False
                continue
            
            # Check for NoBeanDefFoundException handling
            if in_try_block and self.NO_BEAN_DEF_EXCEPTION_PATTERN.search(stripped_line):
                has_exception_handling = True
                continue
            
            # Check for closing brace (end of try-catch)
            if in_try_block and stripped_line == "}":
                in_try_block = False
                has_exception_handling = False
                continue
            
            # Check for unsafe Koin get() calls
            unsafe_koin_get = self.KOIN_UNSAFE_GET_PATTERN.search(stripped_line)
            if unsafe_koin_get:
                # Check if we're in a risky context
                is_risky_context = any(context in file_path for context in self.RISKY_CONTEXTS)
                
                # Check if there's safe getOrNull usage nearby
                context_start = max(0, i - 5)
                context_end = min(len(lines), i + 5)
                context_text = "\n".join(lines[context_start:context_end])
                has_safe_alternative = bool(self.KOIN_SAFE_GET_OR_NULL_PATTERN.search(context_text))
                
                if not has_safe_alternative and (is_risky_context or not in_try_block or not has_exception_handling):
                    severity = "HIGH" if is_risky_context else "MEDIUM"
                    detail = f"Unsafe getKoin().get() call {'in risky context' if is_risky_context else ''} can cause NoBeanDefFoundException. Use getOrNull() or add exception handling."
                    
                    yield {
                        "line_num": line_num,
                        "code": stripped_line,
                        "detail": detail,
                        "severity": severity
                    }


class StrictExceptionHandlingRule(Rule):
    """
    Detects overly specific exception handling that can miss other types of exceptions,
    leading to crashes when unexpected exceptions occur.
    
    This rule specifically targets the pattern shown in GitHub issue #7622 where
    RecipientLoader only catches SecurityException but other exceptions can also occur
    when accessing crypto providers, causing crashes during email composition.
    """
    issue_type = "Overly Specific Exception Handling That Misses Other Exception Types"
    suggestion = "Use more general exception handling (catch Exception) or add multiple specific exception types to prevent crashes from unexpected exceptions."
    
    # Pattern to match overly specific exception catches
    SPECIFIC_EXCEPTION_PATTERN = re.compile(r"catch\s*\(\s*(\w+Exception)\s+\w+\s*\)")
    
    # Pattern to match general exception handling
    GENERAL_EXCEPTION_PATTERN = re.compile(r"catch\s*\(\s*Exception\s+\w+\s*\)")
    
    # Pattern to match multiple exception handling
    MULTIPLE_EXCEPTION_PATTERN = re.compile(r"catch\s*\(\s*(\w+Exception\s*,\s*)*\w+Exception\s+\w+\s*\)")
    
    # Common specific exceptions that might need broader handling
    RISKY_SPECIFIC_EXCEPTIONS = [
        'SecurityException', 'IllegalArgumentException', 'IllegalStateException',
        'NullPointerException', 'IndexOutOfBoundsException', 'UnsupportedOperationException'
    ]
    
    # Contexts where broader exception handling is often needed
    RISKY_CONTEXTS = ['CryptoProvider', 'ContactProvider', 'Database', 'Network', 'FileSystem']

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        # Only analyze Java and Kotlin files
        if not (file_path.endswith('.java') or file_path.endswith('.kt')):
            return
            
        in_try_catch = False
        has_general_exception = False
        has_multiple_exceptions = False
        specific_exceptions = []
        
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped_line = line.strip()
            
            if not stripped_line or stripped_line.startswith("//"):
                continue
            
            # Track try-catch blocks
            if "try" in stripped_line and ("{" in stripped_line or stripped_line.endswith("try")):
                in_try_catch = True
                has_general_exception = False
                has_multiple_exceptions = False
                specific_exceptions = []
                continue
            
            # Check for catch blocks
            if in_try_catch and "catch" in stripped_line:
                # Check for general exception handling
                if self.GENERAL_EXCEPTION_PATTERN.search(stripped_line):
                    has_general_exception = True
                    continue
                
                # Check for multiple exception handling
                if self.MULTIPLE_EXCEPTION_PATTERN.search(stripped_line):
                    has_multiple_exceptions = True
                    continue
                
                # Check for specific exception handling
                specific_match = self.SPECIFIC_EXCEPTION_PATTERN.search(stripped_line)
                if specific_match:
                    exception_type = specific_match.group(1)
                    specific_exceptions.append(exception_type)
                    continue
            
            # Check for closing brace (end of try-catch)
            if in_try_catch and stripped_line == "}":
                in_try_catch = False
                
                # Analyze the exception handling
                if specific_exceptions and not has_general_exception and not has_multiple_exceptions:
                    # Check if we're in a risky context
                    is_risky_context = any(context in file_path for context in self.RISKY_CONTEXTS)
                    
                    # Check if any of the specific exceptions are risky
                    has_risky_exception = any(exc in self.RISKY_SPECIFIC_EXCEPTIONS for exc in specific_exceptions)
                    
                    if has_risky_exception or is_risky_context:
                        severity = "HIGH" if is_risky_context else "MEDIUM"
                        exceptions_str = ", ".join(specific_exceptions)
                        detail = f"Overly specific exception handling (catch {exceptions_str}) {'in risky context' if is_risky_context else ''} may miss other exception types. Consider using broader exception handling or adding more specific exception types."
                        
                        yield {
                            "line_num": line_num,
                            "code": stripped_line,
                            "detail": detail,
                            "severity": severity
                        }
                
                # Reset for next try-catch block
                has_general_exception = False
                has_multiple_exceptions = False
                specific_exceptions = []


class StrictCryptoProviderAccessRule(Rule):
    """
    Detects unsafe access to crypto providers without proper exception handling,
    which can cause crashes when crypto operations fail.
    
    This rule specifically targets patterns where crypto provider access is not
    properly protected against various types of exceptions that can occur during
    cryptographic operations.
    """
    issue_type = "Unsafe Crypto Provider Access Without Comprehensive Exception Handling"
    suggestion = "Add comprehensive exception handling for crypto provider access. Consider catching Exception or multiple specific exception types to handle various failure scenarios."
    
    # Pattern to match crypto provider access
    CRYPTO_PROVIDER_PATTERN = re.compile(r"(cryptoProvider|CryptoProvider|getCryptoProvider|fillContactDataFromCryptoProvider)")
    
    # Pattern to match database/cursor operations
    CURSOR_OPERATION_PATTERN = re.compile(r"(cursor|Cursor|query|Query|getContentResolver)")
    
    # Pattern to match try-catch blocks
    TRY_CATCH_PATTERN = re.compile(r"try\s*\{")
    
    # Pattern to match exception handling
    EXCEPTION_HANDLING_PATTERN = re.compile(r"catch\s*\(\s*(\w+Exception)\s+\w+\s*\)")
    
    # Pattern to match general exception handling
    GENERAL_EXCEPTION_PATTERN = re.compile(r"catch\s*\(\s*Exception\s+\w+\s*\)")
    
    # Common exceptions that can occur with crypto providers
    CRYPTO_EXCEPTIONS = [
        'SecurityException', 'IllegalArgumentException', 'IllegalStateException',
        'NullPointerException', 'UnsupportedOperationException', 'RuntimeException'
    ]

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        # Only analyze Java and Kotlin files
        if not (file_path.endswith('.java') or file_path.endswith('.kt')):
            return
            
        in_try_catch = False
        has_crypto_access = False
        has_general_exception = False
        has_specific_exception = False
        exception_types = []
        
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped_line = line.strip()
            
            if not stripped_line or stripped_line.startswith("//"):
                continue
            
            # Track try-catch blocks
            if self.TRY_CATCH_PATTERN.search(stripped_line):
                in_try_catch = True
                has_crypto_access = False
                has_general_exception = False
                has_specific_exception = False
                exception_types = []
                continue
            
            # Check for crypto provider access
            if in_try_catch and self.CRYPTO_PROVIDER_PATTERN.search(stripped_line):
                has_crypto_access = True
                continue
            
            # Check for exception handling
            if in_try_catch and "catch" in stripped_line:
                # Check for general exception handling
                if self.GENERAL_EXCEPTION_PATTERN.search(stripped_line):
                    has_general_exception = True
                    continue
                
                # Check for specific exception handling
                specific_match = self.EXCEPTION_HANDLING_PATTERN.search(stripped_line)
                if specific_match:
                    exception_type = specific_match.group(1)
                    exception_types.append(exception_type)
                    has_specific_exception = True
                    continue
            
            # Check for closing brace (end of try-catch)
            if in_try_catch and stripped_line == "}":
                in_try_catch = False
                
                # Analyze crypto provider access
                if has_crypto_access and not has_general_exception:
                    if not has_specific_exception:
                        # No exception handling at all
                        severity = "HIGH"
                        detail = "Crypto provider access without any exception handling can cause crashes. Add try-catch block with appropriate exception handling."
                        
                        yield {
                            "line_num": line_num,
                            "code": stripped_line,
                            "detail": detail,
                            "severity": severity
                        }
                    else:
                        # Check if exception handling is comprehensive enough
                        has_comprehensive_handling = any(exc in self.CRYPTO_EXCEPTIONS for exc in exception_types)
                        
                        if not has_comprehensive_handling:
                            severity = "MEDIUM"
                            exceptions_str = ", ".join(exception_types)
                            detail = f"Crypto provider access with limited exception handling (catch {exceptions_str}) may miss other exception types. Consider adding more exception types or using general Exception handling."
                            
                            yield {
                                "line_num": line_num,
                                "code": stripped_line,
                                "detail": detail,
                                "severity": severity
                            }
                
                # Reset for next try-catch block
                has_crypto_access = False
                has_general_exception = False
                has_specific_exception = False
                exception_types = []


class StrictRecipientLayoutValidationRule(Rule):
    """
    Detects unsafe recipient layout operations without proper validation,
    which can cause IllegalArgumentException: Failed requirement crashes.
    
    This rule specifically targets patterns where recipient-related operations
    are performed without checking if recipients exist, similar to the issue
    in RecipientNamesView.onLayout() where createRecipientLayout() is called
    without validating numberOfRecipients.
    """
    issue_type = "Unsafe Recipient Layout Operations Without Validation"
    suggestion = "Add validation checks before performing recipient layout operations. Check if recipients exist (e.g., numberOfRecipients > 0) before calling layout methods to prevent IllegalArgumentException: Failed requirement."
    
    # Pattern to match recipient layout operations
    RECIPIENT_LAYOUT_PATTERN = re.compile(r"(createRecipientLayout|layoutRecipients|drawRecipients|measureRecipients)")
    
    # Pattern to match recipient count variables
    RECIPIENT_COUNT_PATTERN = re.compile(r"(numberOfRecipients|recipientCount|recipients\.size|recipients\.count)")
    
    # Pattern to match zero/empty checks
    ZERO_EMPTY_CHECK_PATTERN = re.compile(r"(\w+)\s*(==\s*0|>\s*0|!=\s*0|\.isEmpty\(\)|\.isNotEmpty\(\))")
    
    # Pattern to match early return statements
    EARLY_RETURN_PATTERN = re.compile(r"return\s*;")
    
    # Pattern to match if statements with validation
    VALIDATION_IF_PATTERN = re.compile(r"if\s*\(\s*(\w+)\s*(==\s*0|>\s*0|!=\s*0|\.isEmpty\(\)|\.isNotEmpty\(\))")
    
    # Methods where recipient validation is critical
    CRITICAL_METHODS = ['onLayout', 'onMeasure', 'onDraw', 'layoutChildren', 'measureChildren']

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        # Only analyze Kotlin and Java files
        if not (file_path.endswith('.kt') or file_path.endswith('.java')):
            return
            
        in_critical_method = False
        method_start = 0
        method_name = ""
        has_validation = False
        has_early_return = False
        
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped_line = line.strip()
            
            if not stripped_line or stripped_line.startswith("//"):
                continue
            
            # Check if we're entering a critical method
            for method in self.CRITICAL_METHODS:
                if f"fun {method}(" in stripped_line or f"void {method}(" in stripped_line or f"override fun {method}(" in stripped_line:
                    in_critical_method = True
                    method_start = i
                    method_name = method
                    has_validation = False
                    has_early_return = False
                    break
            
            # Check if we're exiting the method
            if in_critical_method and stripped_line == "}" and i > method_start:
                if i > 0 and len(lines[i-1].strip()) > 0:
                    prev_indent = len(lines[i-1]) - len(lines[i-1].lstrip())
                    curr_indent = len(line) - len(line.lstrip())
                    if curr_indent <= prev_indent:
                        in_critical_method = False
                        continue
            
            # If we're in a critical method, check for recipient layout operations
            if in_critical_method and self.RECIPIENT_LAYOUT_PATTERN.search(stripped_line):
                # Look for validation in the method
                method_lines = lines[method_start:i+1]
                method_text = "\n".join(method_lines)
                
                # Check if there's validation before this operation
                has_validation = bool(self.ZERO_EMPTY_CHECK_PATTERN.search(method_text))
                has_early_return = bool(self.EARLY_RETURN_PATTERN.search(method_text))
                
                # If no validation found, this is a potential issue
                if not has_validation:
                    severity = "HIGH"
                    detail = f"Recipient layout operation in {method_name}() without validation. This can cause IllegalArgumentException: Failed requirement when no recipients exist."
                    
                    yield {
                        "line_num": line_num,
                        "code": stripped_line,
                        "detail": detail,
                        "severity": severity
                    }
                elif has_validation and not has_early_return:
                    # Has validation but no early return - medium severity
                    severity = "MEDIUM"
                    detail = f"Recipient layout operation in {method_name}() with validation but no early return. Consider adding early return when no recipients exist for better performance."
                    
                    yield {
                        "line_num": line_num,
                        "code": stripped_line,
                        "detail": detail,
                        "severity": severity
                    }
class StrictFailedRequirementExceptionRule(Rule):
    """
    Detects patterns that can lead to IllegalArgumentException: Failed requirement
    exceptions, which are common in Android UI operations when preconditions are not met.
    
    This rule specifically targets patterns where operations are performed without
    checking preconditions, leading to "Failed requirement" exceptions.
    """
    issue_type = "Potential IllegalArgumentException: Failed Requirement"
    suggestion = "Add precondition checks before performing operations that can throw IllegalArgumentException: Failed requirement. Validate inputs and state before calling methods that have strict requirements."
    
    # Pattern to match operations that commonly throw "Failed requirement"
    FAILED_REQUIREMENT_OPERATIONS = [
        'createLayout', 'layoutChildren', 'measureChildren', 'onLayout', 'onMeasure',
        'createRecipientLayout', 'layoutRecipients', 'drawRecipients',
        'setScale', 'setRotation', 'setTranslation', 'setAlpha',
        'addView', 'removeView', 'removeViewAt'
    ]
    
    # Pattern to match size/count checks
    SIZE_COUNT_CHECK_PATTERN = re.compile(r"(\w+)\s*(==\s*0|>\s*0|!=\s*0|\.isEmpty\(\)|\.isNotEmpty\(\)|\.size\s*==\s*0|\.count\s*==\s*0)")
    
    # Pattern to match null checks
    NULL_CHECK_PATTERN = re.compile(r"(\w+)\s*(==\s*null|!=\s*null)")
    
    # Pattern to match early return statements
    EARLY_RETURN_PATTERN = re.compile(r"return\s*;")
    
    # Pattern to match if statements with validation
    VALIDATION_IF_PATTERN = re.compile(r"if\s*\(\s*(\w+)\s*(==\s*0|>\s*0|!=\s*0|\.isEmpty\(\)|\.isNotEmpty\(\)|==\s*null|!=\s*null)")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        # Only analyze Kotlin and Java files
        if not (file_path.endswith('.kt') or file_path.endswith('.java')):
            return
            
        in_method = False
        method_start = 0
        method_name = ""
        has_validation = False
        has_early_return = False
        
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped_line = line.strip()
            
            if not stripped_line or stripped_line.startswith("//"):
                continue
            
            # Check if we're entering a method
            if "fun " in stripped_line or "void " in stripped_line or "override fun " in stripped_line:
                in_method = True
                method_start = i
                method_name = stripped_line.split('(')[0].split()[-1]
                has_validation = False
                has_early_return = False
                continue
            
            # Check if we're exiting the method
            if in_method and stripped_line == "}" and i > method_start:
                if i > 0 and len(lines[i-1].strip()) > 0:
                    prev_indent = len(lines[i-1]) - len(lines[i-1].lstrip())
                    curr_indent = len(line) - len(line.lstrip())
                    if curr_indent <= prev_indent:
                        in_method = False
                        continue
            
            # If we're in a method, check for operations that can throw "Failed requirement"
            if in_method:
                for operation in self.FAILED_REQUIREMENT_OPERATIONS:
                    if operation in stripped_line:
                        # Look for validation in the method
                        method_lines = lines[method_start:i+1]
                        method_text = "\n".join(method_lines)
                        
                        # Check if there's validation before this operation
                        has_validation = bool(self.SIZE_COUNT_CHECK_PATTERN.search(method_text) or 
                                            self.NULL_CHECK_PATTERN.search(method_text))
                        has_early_return = bool(self.EARLY_RETURN_PATTERN.search(method_text))
                        
                        # If no validation found, this is a potential issue
                        if not has_validation:
                            severity = "HIGH"
                            detail = f"Operation '{operation}' without validation in {method_name}() can cause IllegalArgumentException: Failed requirement. Add precondition checks."
                            
                            yield {
                                "line_num": line_num,
                                "code": stripped_line,
                                "detail": detail,
                                "severity": severity
                            }
                        elif has_validation and not has_early_return:
                            # Has validation but no early return - medium severity
                            severity = "MEDIUM"
                            detail = f"Operation '{operation}' in {method_name}() with validation but no early return. Consider adding early return when preconditions are not met."
                            
                            yield {
                                "line_num": line_num,
                                "code": stripped_line,
                                "detail": detail,
                                "severity": severity
                            }
                        break


class StrictWithResumedUsageRule(Rule):
    """
    Detects repeatOnLifecycle(Lifecycle.State.RESUMED) used where withResumed would be safer/simpler.

    Based on PR replacing repeatOnLifecycle(State.RESUMED) blocks with withResumed { ... } to avoid
    IllegalStateException with fragment/activity transactions after onSaveInstanceState.
    """
    issue_type = "Use withResumed instead of repeatOnLifecycle(State.RESUMED)"
    suggestion = "Replace repeatOnLifecycle(State.RESUMED) { ... } with withResumed { ... } when doing UI/navigation actions."

    REPEAT_ON_RESUMED_PATTERN = re.compile(r"repeatOnLifecycle\s*\(\s*Lifecycle\.State\.RESUMED\s*\)")
    UI_ACTION_HINT_PATTERN = re.compile(r"(navigate|open|show|launch|commit|replace|fullScroll|isVisible|isGone|isInvisible)")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        if not (file_path.endswith('.kt') or file_path.endswith('.java')):
            return

        for i, raw in enumerate(lines):
            s = raw.strip()
            if not s or s.startswith("//"):
                continue

            if self.REPEAT_ON_RESUMED_PATTERN.search(s):
                # Look ahead a small window for UI actions inside the block
                window_end = min(len(lines), i + 12)
                window_text = "\n".join(x.strip() for x in lines[i:window_end])
                has_ui_action = bool(self.UI_ACTION_HINT_PATTERN.search(window_text))
                severity = "HIGH" if has_ui_action else "MEDIUM"
                detail = "repeatOnLifecycle(RESUMED) used for UI/navigation; prefer withResumed to avoid state issues."
                yield {
                    "line_num": i + 1,
                    "code": s,
                    "detail": detail,
                    "severity": severity,
                }


class StrictRepeatOnLifecycleCreatedInitRule(Rule):
    """
    Detects repeatOnLifecycle(Lifecycle.State.CREATED) used for one-shot initialization calls
    (e.g., mapView.initialize), where a simple direct call or lifecycleScope.launch is sufficient.
    """
    issue_type = "Avoid repeatOnLifecycle(CREATED) for one-shot initialization"
    suggestion = "Call initialization directly or from lifecycleScope without repeatOnLifecycle(CREATED)."

    REPEAT_ON_CREATED_PATTERN = re.compile(r"repeatOnLifecycle\s*\(\s*Lifecycle\.State\.CREATED\s*\)")
    ONE_SHOT_INIT_HINT_PATTERN = re.compile(r"(initialize\s*\(|setup\s*\(|bind\s*\(|load\s*\(|onCreate\s*\()")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        if not (file_path.endswith('.kt') or file_path.endswith('.java')):
            return

        for i, raw in enumerate(lines):
            s = raw.strip()
            if not s or s.startswith("//"):
                continue

            if self.REPEAT_ON_CREATED_PATTERN.search(s):
                window_end = min(len(lines), i + 10)
                window_text = "\n".join(x.strip() for x in lines[i:window_end])
                is_one_shot = bool(self.ONE_SHOT_INIT_HINT_PATTERN.search(window_text))
                if is_one_shot:
                    yield {
                        "line_num": i + 1,
                        "code": s,
                        "detail": "repeatOnLifecycle(CREATED) wrapping a one-shot initializer; invoke directly instead.",
                        "severity": "LOW",
                    }


# FileProvider authority safety rules
class StrictFileProviderAuthorityRule(Rule):
    """
    Detects using the wrong BuildConfig when constructing FileProvider authority or
    hard-coded foreign authority, which can cause IllegalArgumentException at runtime.
    """
    issue_type = "Incorrect FileProvider authority"
    suggestion = "Use the host app applicationId when building authority (applicationId + '.provider'); avoid library BuildConfig."

    WRONG_AUTH_PATTERN = re.compile(r"FileProvider\.getUriForFile\s*\([^,]+,\s*([\w\.]+)\.BuildConfig\.APPLICATION_ID\s*\+\s*\"\\.provider\"")
    HARD_CODED_FOREIGN_PATTERN = re.compile(r"FileProvider\.getUriForFile\s*\([^,]+,\s*\"[a-zA-Z0-9_\.]+\.provider\"")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        if not (file_path.endswith('.java') or file_path.endswith('.kt')):
            return

        for i, raw in enumerate(lines):
            s = raw.strip()
            if not s or s.startswith("//"):
                continue

            if self.WRONG_AUTH_PATTERN.search(s):
                yield {
                    "line_num": i + 1,
                    "code": s,
                    "detail": "FileProvider authority built from library BuildConfig.APPLICATION_ID; may not match host app.",
                    "severity": "HIGH",
                }

            if self.HARD_CODED_FOREIGN_PATTERN.search(s) and "BuildConfig.APPLICATION_ID" not in s and "+ \".provider\"" not in s:
                yield {
                    "line_num": i + 1,
                    "code": s,
                    "detail": "Hard-coded authority may not match applicationId; prefer applicationId + '.provider'.",
                    "severity": "MEDIUM",
                }


class StrictFileProviderHelperSignatureRule(Rule):
    """
    Detects helper methods wrapping FileProvider.getUriForFile(...) that don't accept
    applicationId parameter, encouraging callers to pass correct app id explicitly.
    """
    issue_type = "FileProvider helper missing applicationId parameter"
    suggestion = "Add applicationId parameter to helper and use it to build authority."

    JAVA_HELPER_PATTERN = re.compile(r"public\s+static\s+[\w\.]+\s+getUriFromFile\s*\(\s*Context\s+\w+\s*,\s*File\s+\w+\s*\)")
    KOTLIN_HELPER_PATTERN = re.compile(r"fun\s+getUriFromFile\s*\(\s*context\s*:\s*Context\s*,\s*file\s*:\s*File\s*\)")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        if not (file_path.endswith('.java') or file_path.endswith('.kt')):
            return

        for i, raw in enumerate(lines):
            s = raw.strip()
            if not s or s.startswith("//"):
                continue

            if self.JAVA_HELPER_PATTERN.search(s) or self.KOTLIN_HELPER_PATTERN.search(s):
                yield {
                    "line_num": i + 1,
                    "code": s,
                    "detail": "Helper should accept applicationId and avoid using library BuildConfig.APPLICATION_ID.",
                    "severity": "MEDIUM",
                }

class StrictSponsorBlockApiUrlRule(Rule):
    """
    Detects SponsorBlock API submissions using an empty or invalid API URL, leading to
    IllegalArgumentException from OkHttp (missing http/https scheme).

    Mirrors the fix replacing "" with a valid apiUrl when calling submitSponsorBlockSegment(...).
    """
    issue_type = "SponsorBlock submit with empty/invalid API URL"
    suggestion = "Pass a valid http/https base URL (e.g., apiUrl) to submitSponsorBlockSegment instead of an empty string."

    # Match submitSponsorBlockSegment(..., <segment>, "") or literal without scheme
    EMPTY_URL_CALL_PATTERN = re.compile(r"submitSponsorBlockSegment\s*\([^\)]*,\s*\"\"\s*\)")
    LITERAL_URL_CALL_PATTERN = re.compile(r"submitSponsorBlockSegment\s*\([^\)]*,\s*\"([^\"]+)\"\s*\)")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        if not (file_path.endswith('.java') or file_path.endswith('.kt')):
            return

        for i, raw in enumerate(lines):
            s = raw.strip()
            if not s or s.startswith("//"):
                continue

            if self.EMPTY_URL_CALL_PATTERN.search(s):
                yield {
                    "line_num": i + 1,
                    "code": s,
                    "detail": "submitSponsorBlockSegment called with empty apiUrl string.",
                    "severity": "HIGH",
                }

            m = self.LITERAL_URL_CALL_PATTERN.search(s)
            if m:
                literal = m.group(1)
                if not (literal.startswith("http://") or literal.startswith("https://")):
                    yield {
                        "line_num": i + 1,
                        "code": s,
                        "detail": "submitSponsorBlockSegment uses a URL literal without http/https scheme.",
                        "severity": "HIGH",
                    }


class StrictHttpUrlSchemeRule(Rule):
    """
    Detects OkHttp Request/HttpUrl usage with string literals lacking http/https schemes or empty strings.
    """
    issue_type = "OkHttp URL without http/https scheme"
    suggestion = "Ensure Request.Builder().url(...) and HttpUrl.get(...) receive a non-empty http/https URL."

    REQUEST_BUILDER_URL_PATTERN = re.compile(r"Request\.Builder\s*\(\)\.url\s*\(\s*\"([^\"]*)\"\s*\)")
    HTTPURL_GET_PATTERN = re.compile(r"HttpUrl\.(get|Companion\.get)\s*\(\s*\"([^\"]*)\"\s*\)")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        if not (file_path.endswith('.java') or file_path.endswith('.kt')):
            return

        for i, raw in enumerate(lines):
            s = raw.strip()
            if not s or s.startswith("//"):
                continue

            m1 = self.REQUEST_BUILDER_URL_PATTERN.search(s)
            if m1:
                literal = m1.group(1)
                if literal == "" or not (literal.startswith("http://") or literal.startswith("https://")):
                    yield {
                        "line_num": i + 1,
                        "code": s,
                        "detail": "Request.Builder().url(...) is given an empty or non-http(s) literal.",
                        "severity": "HIGH",
                    }

            m2 = self.HTTPURL_GET_PATTERN.search(s)
            if m2:
                literal = m2.group(2)
                if literal == "" or not (literal.startswith("http://") or literal.startswith("https://")):
                    yield {
                        "line_num": i + 1,
                        "code": s,
                        "detail": "HttpUrl.get(...) is given an empty or non-http(s) literal.",
                        "severity": "HIGH",
                    }


class StrictFragmentDialogStateLossRule(Rule):
    """
    Detects DialogFragment/show() usage from a Fragment without guarding against state loss.

    Requires checking fragment.isAdded() and !fragment.isStateSaved() before showing dialogs.
    """
    issue_type = "Dialog shown after onSaveInstanceState (state loss risk)"
    suggestion = "Check isAdded() and !isStateSaved() before calling show() on a dialog or FragmentManager."

    SHOW_DIALOG_PATTERN = re.compile(r"\.show\s*\(\s*.*(getChildFragmentManager\(|getParentFragmentManager\(|getSupportFragmentManager\()")
    IS_ADDED_CHECK_PATTERN = re.compile(r"isAdded\s*\(\s*\)")
    IS_STATE_SAVED_NEG_PATTERN = re.compile(r"!\s*isStateSaved\s*\(\s*\)")

    def analyze_file(self, file_path: str, lines: List[str]) -> Generator[Dict[str, Any], None, None]:
        if not (file_path.endswith('.java') or file_path.endswith('.kt')):
            return

        for i, raw in enumerate(lines):
            s = raw.strip()
            if not s or s.startswith("//"):
                continue

            if self.SHOW_DIALOG_PATTERN.search(s):
                # Look back a small window for guards
                window_start = max(0, i - 8)
                window_text = "\n".join(x.strip() for x in lines[window_start:i+1])
                has_is_added = bool(self.IS_ADDED_CHECK_PATTERN.search(window_text))
                has_not_state_saved = bool(self.IS_STATE_SAVED_NEG_PATTERN.search(window_text))

                if not (has_is_added and has_not_state_saved):
                    yield {
                        "line_num": i + 1,
                        "code": s,
                        "detail": "Dialog shown without checking isAdded() and !isStateSaved(); can crash after onSaveInstanceState.",
                        "severity": "HIGH",
                    }

# --- 3. Scanner Engine ---

class CodeScanner:
    """
    Engine responsible for traversing the code repository and applying all registered rules.
    """
    def __init__(self, rules: List[Rule]):
        if not rules:
            raise ValueError("CodeScanner must be initialized with at least one rule.")
        self.rules = rules
        print(f"✅ Scanner engine initialized, loaded {len(self.rules)} rules: {[rule.name for rule in rules]}")

    def scan_repository(self, repo_path: str) -> List[Dict[str, Any]]:
        """
        Scan the entire code repository.

        Args:
            repo_path (str): Local path to the Android repository.

        Returns:
            List[Dict[str, Any]]: List of all discovered issues.
        """
        all_issues = []
        for root, _, files in os.walk(repo_path):
            for file in files:
                if file.endswith(".kt") or file.endswith(".java"):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            lines = f.readlines()
                        
                        for rule in self.rules:
                            # Run analysis for each file and each rule
                            for issue in rule.analyze_file(file_path, lines):
                                all_issues.append(self._format_issue(file_path, rule, issue))

                    except Exception as e:
                        print(f"❌ Error processing file {file_path}: {e}")
        return all_issues

    def _format_issue(self, file_path: str, rule: Rule, issue_details: Dict[str, Any]) -> Dict[str, Any]:
        """Unified formatting output."""
        # Get context code (10 lines above and below)
        context_lines = self._get_context_lines(file_path, issue_details["line_num"], 10)
        
        return {
            "file_path": file_path,
            "line_num": issue_details["line_num"],
            "issue_type": rule.issue_type,
            "code": issue_details["code"],
            "context_code": context_lines,
            "suggestion": rule.suggestion,
            "rule_name": rule.name,
            "detail": issue_details.get("detail", "")
        }
    
    def _get_context_lines(self, file_path: str, target_line: int, context_size: int = 10) -> str:
        """Get context code around the target line."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            start_line = max(0, target_line - context_size - 1)  # Convert to 0-index
            end_line = min(len(lines), target_line + context_size)  # target_line is already 1-index
            
            context_lines = []
            for i in range(start_line, end_line):
                line_num = i + 1
                prefix = ">>> " if line_num == target_line else "    "
                context_lines.append(f"{prefix}{line_num:4d}: {lines[i].rstrip()}")
            
            return "\n".join(context_lines)
        except Exception as e:
            return f"Unable to get context code: {e}"

# --- 4. Main Program Entry ---

def report_issues(issues: List[Dict[str, Any]]):
    """Format and print the scanning report."""
    if not issues:
        print("\n🎉 Scan completed! No issues found.")
        return

    print(f"\n🚨 Scan completed! Found {len(issues)} potential issues:")
    
    # Group issues by file path
    issues_by_file = {}
    for issue in issues:
        if issue['file_path'] not in issues_by_file:
            issues_by_file[issue['file_path']] = []
        issues_by_file[issue['file_path']].append(issue)

    for file_path, file_issues in issues_by_file.items():
        print("\n" + "=" * 80)
        print(f"📄 File: {file_path}")
        print("=" * 80)
        for issue in sorted(file_issues, key=lambda x: x['line_num']):
            severity = issue.get('severity', 'UNKNOWN')
            severity_icon = "🔴" if severity == "HIGH" else "🟡" if severity == "MEDIUM" else "🟢" if severity == "LOW" else "⚪"
            print(f"  - {severity_icon} [L{issue['line_num']}] {issue['issue_type']} ({severity})")
            print(f"    Code: `{issue['code']}`")
            print(f"    Context:")
            print(f"    {issue.get('context_code', 'No context information')}")
            print(f"    Suggestion: {issue['suggestion']}")
            if issue['detail']:
                print(f"    Detail: {issue['detail']}")
            print("-" * 40)

def main():
    # ================================================================= #
    # == To add new rules in the future, just instantiate and add to all_rules list == #
    # ================================================================= #
    all_rules = [
        # UnsafeStartActivityRule(),
        # UnsafeBrowserIntentRule(),
        # StrictFragmentBindingRule(),
        # UnsafeArrayIndexAccessRule(),
        # UnsafeNullComparisonRule(),
        # UnsafeParcelableIntentRule(),
        # UnsafeCollectionAccessRule(),
        # UnsafeFragmentBindingAccessRule(),
        # UnsafeNullableObjectAccessRule(),
        # UnsafeServiceLifecycleAccessRule(),
        # UnsafeSystemServiceCallRule(),
        # UnsafeFileSystemOperationRule(),
        # UnsafeMathematicalFunctionRule(),
        # UnsafeAndroidPermissionRule(),
        # UnsafeRtlLayoutRule(),
        # UnsafeStorageOperationRule(),
        # UnsafeLibraryApiMigrationRule(),
        # UnsafeParentChildStateRule(),
        # IncompleteEqualsMethodRule(),
        # MissingStateCheckRule(),
        # UnsafeCollectionAccessRule(),
        # InconsistentStateManagementRule(),
        # UnsafeJsonDeserializationRule(),
        # UnsafeListDeduplicationRule(),
        # UnsafeDateFormatterRule(),
        # UnsafeForegroundServiceStartRule(),
        # StrictServiceBindStartConsistencyRule(),
        # UnsafeDatabaseEntitySerializationRule(),
        # StrictKotlinRoomEntitySerializationRule(),
        # StrictMlKitScannerVisibilityRule(),
        # StrictPhotoViewScaleBoundsRule(),
        # StrictQtModelDbMutexRule(),
        # StrictQtSqlExplicitBindIndexRule(),
        # StrictSqlLikeEscapingRule(),
        # StrictSafeUriParsingRule(),
        # StrictCryptoAddressValidationCatchRule(),
        # StrictEthereumTxPaginationSqlRule(),
        # StrictEip20SupportBlockchainGuardRule(),
        # StrictHandledExceptionCatchRule(),
        # StrictTmdbRatingNormalizationRule(),
        # StrictPlaybackReportNullGuardRule(),
        # StrictBottomSheetTargetStateRule(),
        # StrictMediaPlaybackWakeLockPermissionRule(),
        # StrictBackupImportValidationRule(),
        # StrictGroupieStartDragViewHolderRule(),
        # StrictRxSubscribeErrorHandlerRule(),
        # StrictPaidContentExceptionRule(),
        # StrictMediaServiceForegroundStartRule(),
        # StrictNullGuardBeforePlayerUsageRule(),
        IncompleteBooleanConditionRule(),
        StrictEmptyRecipientHeadersRule(),
        StrictSwipeCallbackNullCheckRule(),
        StrictWorkerFactoryNullSafetyRule(),
        StrictKoinDependencyInjectionRule(),
        StrictExceptionHandlingRule(),
        StrictCryptoProviderAccessRule(),
        StrictLiveDataListTerminalOpRule(),
        StrictNonNullAssertionTerminalOpRule(),
        StrictWithResumedUsageRule(),
        StrictRepeatOnLifecycleCreatedInitRule(),
        StrictRxSubscribeErrorHandlerRule(),
        StrictRxIoThreadingForWritesRule(),
        StrictFileProviderAuthorityRule(),
        StrictFileProviderHelperSignatureRule(),
        StrictQuickTileForegroundStartRule(),
        StrictTilePendingIntentWorkaroundRule(),
        StrictPlayerNullGuardRule(),
        StrictSponsorBlockApiUrlRule(),
        StrictHttpUrlSchemeRule(),
        StrictFragmentDialogStateLossRule(),
        StrictPeertubeChannelIdParsingRule(),
        StrictRecipientLayoutValidationRule(),
        StrictFailedRequirementExceptionRule(),
    ]

    scanner = CodeScanner(rules=all_rules)
    
    repo_to_scan = "/path/repo_root/xxx"

    if not os.path.isdir(repo_to_scan):
        print(f"Error: Path '{repo_to_scan}' is not a valid directory.")
        return

    print("\n🚀 Starting project scan...")
    found_issues = scanner.scan_repository(repo_to_scan)
    report_issues(found_issues)


if __name__ == "__main__":
    main()