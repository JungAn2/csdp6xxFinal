# read this github repo and going to utilize this along with AI
https://github.com/AryaD123/real-time-event-logs

## Description
The program will take the event logs (which looks to be in JSON format) and store that in rag database. Then it will use AI to analyze the logs and provide insights. This is zero trust security that the insight will be focused on. It will analyze the logs and provide insights on the following:
- Authorization
- Authentication
- Data
- Device
- Network
- User

It will flag if the user is trying to access the system without proper authorization or that user is behaving abnormally such as accessing at unusual hours or accessing at unusual locations. Even accessing unauthorized data or devices will be flagged.

Since the server will not be live when demo, I will provide inital logs to start with. The frontend will then auto generate (number from 1 to 100 depending on the user) activities and the AI will analyze them in real time. The real time in this case will be every 5 seconds.

Use langchain to allow multiple AI modles to be used. use .env file to store the API keys. The following AI models should be able to be used:
- OpenAI
- Anthropic
- Google
Only one of the model will be used at a time. The user will be able to select which model to use.

python library to use:
- langchain
- rag (which is best for this project)
- gradio
- and others as needed