from langchain_openai import ChatOpenAI
text = """// 165:     // Cleanup
// 166:     free_sip_msg(msg);
// 167:     free(body);
// 168: 
// 169:     return 0;
// 170: }"""


llm = ChatOpenAI(model="gpt-4.1")
print(llm.temperature)