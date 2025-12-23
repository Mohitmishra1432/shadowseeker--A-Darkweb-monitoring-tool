import axios from 'axios';
import { SocksProxyAgent } from 'socks-proxy-agent';

export class TorService {
  private static readonly TOR_PROXY = 'socks5://127.0.0.1:9050';
  private static agent: SocksProxyAgent;

  static initialize() {
    this.agent = new SocksProxyAgent(this.TOR_PROXY);
  }

  static async crawlOnionSite(url: string): Promise<any> {
    if (!this.agent) {
      this.initialize();
    }

    try {
      const response = await axios.get(url, {
        httpsAgent: this.agent,
        timeout: 30000,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0'
        }
      });

      return {
        success: true,
        data: response.data,
        status: response.status,
        url: url
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
        url: url
      };
    }
  }

  static async searchOnionSites(keyword: string, sites: string[] = []) {
    const results = [];
    
    for (const site of sites) {
      try {
        const result = await this.crawlOnionSite(site);
        if (result.success) {
          // Basic content analysis for keyword
          const content = result.data.toLowerCase();
          const keywordFound = content.includes(keyword.toLowerCase());
          
          results.push({
            site,
            keywordFound,
            status: result.status,
            snippet: keywordFound ? this.extractSnippet(content, keyword) : 'Keyword not found'
          });
        } else {
          results.push({
            site,
            keywordFound: false,
            error: result.error,
            status: 'Failed'
          });
        }
      } catch (error) {
        results.push({
          site,
          keywordFound: false,
          error: 'Crawl failed',
          status: 'Error'
        });
      }
    }

    return results;
  }

  private static extractSnippet(content: string, keyword: string, wordsAround: number = 20): string {
    const index = content.indexOf(keyword.toLowerCase());
    if (index === -1) return '';
    
    const start = Math.max(0, index - wordsAround * 10);
    const end = Math.min(content.length, index + keyword.length + wordsAround * 10);
    
    return content.substring(start, end).replace(/[^\w\s]/g, ' ').substring(0, 200) + '...';
  }
}