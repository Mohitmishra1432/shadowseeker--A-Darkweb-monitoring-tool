const { SocksProxyAgent } = require('socks-proxy-agent');

console.log('🧪 Testing Tor Connection...');

// Test both common Tor ports
const ports = [9050, 9150];

async function testTor() {
  for (const port of ports) {
    console.log(`\n🔧 Testing port ${port}...`);
    
    try {
      const torAgent = new SocksProxyAgent(`socks5://127.0.0.1:${port}`);
      
      // Test with a simple HTTP request through Tor
      const https = require('https');
      
      const options = {
        hostname: 'checkip.amazonaws.com',
        port: 443,
        path: '/',
        method: 'GET',
        agent: torAgent
      };
      
      const response = await new Promise((resolve, reject) => {
        const req = https.request(options, (res) => {
          let data = '';
          res.on('data', chunk => data += chunk);
          res.on('end', () => resolve(data));
        });
        
        req.on('error', reject);
        req.setTimeout(10000, () => reject(new Error('Timeout')));
        req.end();
      });
      
      console.log(`✅ Tor connected on port ${port}!`);
      console.log(`🌐 Your Tor IP: ${response.trim()}`);
      return true;
      
    } catch (error) {
      console.log(`❌ Port ${port} failed: ${error.message}`);
    }
  }
  
  console.log('\n❌ Tor is not running on any standard port.');
  console.log('Please make sure Tor Browser is running AND connected to Tor network.');
  return false;
}

testTor();