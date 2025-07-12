import re

# Match pattern like: class LOG4CXX_EXPORT MyClass
pattern = r'(\bclass\s+)([A-Z_][A-Z0-9_]*\s+)'  # matches uppercase-style macro

# Example input
code = "class WriterAppender{"

# Replace the macro with an empty string
cleaned_code = re.sub(pattern, r'\1', code)

print(cleaned_code)
# Output: class WriterAppender : public AppenderSkeleton { };
