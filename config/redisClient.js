import { createClient } from 'redis';

const client = createClient();

client.on('error', (err) => console.log('Redis Client Error', err));

async function connectToRedis() {
  try {
    await client.connect();
    console.log('Connected to Redis!');
  } catch (err) {
    console.error('Redis Connection Error:', err);
  }
}

connectToRedis(); 

export default client; 
