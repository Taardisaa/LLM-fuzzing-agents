from utils.misc import extract_name

funclist = [
#    ( "struct url ada::url_aggregator ada::parser::parse_url<ada::url_aggregator>(string_view, const struct url *)", "parse_url"),
#    ("struct url ada::url ada::parser::parse_url<ada::url>(string_view, const struct url *)", "parse_url"),
#    ("basic_regex<char, boost::regex_traits<char, boost::cpp_regex_traits<char> > > & boost::basic_regex<char, boost::c_regex_traits<char> >::assign(basic_regex<char, boost::regex_traits<char, boost::cpp_regex_traits<char> > > *, const char *, const char *, flag_type)", "boost::basic_regex<char, boost::c_regex_traits<char> >::assign"),
    ("SuggestionList & (anonymous namespace)::SuggestImpl::suggest(const char *);", "SuggestImpl::suggest"),
]

import re

def extract_namespace_and_name(function_signature: str) -> tuple[str, str]:
    """
    Extracts the namespace/class and function name from a C++ function signature.
    Returns (namespace, function_name).
    """
    # Remove parameters
    signature = function_signature.split('(')[0].strip()
    # Regex to match namespace::function or Class::function
    match = re.search(r'([a-zA-Z0-9_:<>,\s*&]+)::([~a-zA-Z0-9_]+)$', signature)
    if match:
        namespace = match.group(1).strip()
        function_name = match.group(2).strip()
        return namespace, function_name
    else:
        # Fallback: no namespace
        tokens = signature.split()
        return "", tokens[-1] if tokens else ""

for func in funclist:
    full_name = extract_name(func[0], keep_namespace=True)

    print(f"Full name: {full_name}")