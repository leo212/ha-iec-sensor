from api import API
import asyncio

async def test():
    api = API("040966277", "leo212@mailsac.com", "k_FH1lW6HQ6FJ8KMhJti8mNXNXZc0yP9VNpzwd97f")    
    token = await api.get_token()    
    result = await api.fetch(token)
    print(result)


asyncio.get_event_loop().run_until_complete(test())