const axios = require('axios');
const Parser = require('rss-parser');
const fs = require('fs');
const { RandomForestClassifier } = require('ml-randomforest'); 

const parser = new Parser();

const feeds = [
  'http://feeds.feedburner.com/Unit42',
  'https://www.proofpoint.com/us/rss.xml',
  'https://blog.pulsedive.com/rss/',
  'https://blog.qualys.com/vulnerabilities-threat-research/feed',
  'https://www.recordedfuture.com/feed',
  'https://securelist.com/feed/',
  'https://socprime.com/blog/feed/',
  'https://blogs.quickheal.com/author/threat-research-labs/feed/',
  'https://www.reliaquest.com/blog/category/threat-hunting/feed/',
  'https://www.reliaquest.com/blog/category/threat-intelligence/feed/',
  'https://securitylit.medium.com/feed',
  'https://sensepost.com/rss.xml',
  'https://www.sentinelone.com/labs/feed/',
  'https://www.seqrite.com/blog/feed/',
  'https://blog.sekoia.io/category/research-threat-intelligence/feed/',
  'https://news.sophos.com/en-us/category/threat-research/feed/',
  'https://posts.specterops.io/feed',
  'https://www.team-cymru.com/blog-feed.xml',
  'https://therecord.media/feed/',
  'https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/rss.xml',
  'https://www.upguard.com/breaches/rss.xml'
];

const apiKey = '43cba56d030f59e374adfa655f812ec0f42ce8b9b54335eb1ef994cb841edbb1';

const fetchAndParseFeeds = async () => {
  let threatData = [];

  for (let feedUrl of feeds) {
    try {
      const response = await axios.get(feedUrl);
      const feed = await parser.parseString(response.data);

      console.log(`Feed Title: ${feed.title}`);
      feed.items.forEach(item => {
        console.log(`Title: ${item.title}`);
        console.log(`Link: ${item.link}`);
        console.log(`PubDate: ${item.pubDate}`);
        console.log('-----------------------------------');

        // Collect URLs for threat intelligence
        threatData.push({ title: item.title, link: item.link, pubDate: item.pubDate });
      });

      // Save the parsed data to a file
      const fileName = feed.title.replace(/[^a-z0-9]/gi, '_').toLowerCase() + '.json';
      fs.writeFileSync(fileName, JSON.stringify(feed, null, 2));
    } catch (error) {
      console.error(`Error fetching or parsing feed: ${feedUrl}`, error);
    }
  }

  // Proceed to get threat scores and predict severity
  await getThreatScores(threatData);
};

const getThreatScores = async (threatData) => {
  let threatScores = [];

  for (let threat of threatData) {
    try {
      const report = await getVirusTotalReport(threat.link);
      if (report) {
        const positives = report.positives || 0;
        const total = report.total || 0;
        const score = total ? positives / total : 0;
        threatScores.push(score);
      }
    } catch (error) {
      console.error(`Error fetching VirusTotal report for ${threat.link}:`, error);
    }
  }

  // Save threat scores to a JSON file
  fs.writeFileSync('threat_scores.json', JSON.stringify(threatScores, null, 2));

  console.log('Threat scores saved to threat_scores.json');

  // Train machine learning model and predict severity
  await trainAndPredictSeverity(threatScores);
};

const trainAndPredictSeverity = async (threatScores) => {
  // Assuming you have historical data for training (X_train, y_train)

  try {
    const model = new RandomForestClassifier();
    // Train the model with historical threat data
    // Replace with actual training data
    const X_train = [
      [0.1], [0.4], [0.3], [0.5]
    ]; // example feature vectors
    const y_train = [0, 1, 0, 1]; // example labels corresponding to X_train
    model.train(X_train, y_train);

    // Example prediction using the last threat score
    const prediction = model.predict([threatScores[threatScores.length - 1]]);
    console.log('Predicted severity:', prediction);
  } catch (error) {
    console.error('Error training or predicting severity:', error);
  }
};

const getVirusTotalReport = async (url) => {
  const baseUrl = 'https://www.virustotal.com/vtapi/v2/url/report';
  try {
    const response = await axios.get(baseUrl, {
      params: {
        apikey: apiKey,
        resource: url,
        scan: 1
      }
    });
    return response.data;
  } catch (error) {
    console.error(`Error fetching VirusTotal report:`, error);
    return null;
  }
};

fetchAndParseFeeds();
