import tiktoken

text = "// This is an example sentence."
encoding = tiktoken.encoding_for_model("gpt-3.5-turbo") # Or your model
tokens = encoding.encode(text)
num_tokens = len(tokens)
print(tokens)
print(f"Number of tokens: {num_tokens}")