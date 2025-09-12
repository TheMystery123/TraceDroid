from openai import OpenAI



class GptModel:
    client = OpenAI(
        api_key="xxxxxx",
        base_url="xxx/v1"
    )

    def chat(self, question: str):
        chat_completion = self.client.chat.completions.create(
            messages=[
                {
                    "role": "user",
                    "content": question,
                }
            ],
            model="gpt-4o",
        )

        return chat_completion.choices[0].message.content

if __name__ == '__main__':
    model = GptModel()
    print(model.chat("hello"))