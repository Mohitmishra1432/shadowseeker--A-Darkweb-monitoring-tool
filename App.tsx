import React, { useState, useEffect } from "react";
import Sidebar from "./components/Sidebar";
import Topbar from "./components/Topbar";
import Metrics from "./components/Metrics";
import ThreatFeed from "./components/ThreatFeed";
import ActivityTimeline from "./components/ActivityTimeline";
import DataFlow from "./components/DataFlow";
import ActorProfiles from "./components/ActorProfiles";
import CaseManagement from "./components/CaseManagement";
import Watchlist from "./components/Watchlist";
import GeoMap from "./components/GeoMap";
import TorCrawler from "./components/TorCrawler";
import AdvancedSearch from "./components/AdvancedSearch";
import AlertSystem from "./components/AlertSystem";
import ExportManager from "./components/ExportManager";
import Dashboard from "./components/Dashboard";
import Login from "./components/Login";
import "./App.css";

const App: React.FC = () => {
  // Dashboard State
  const [query, setQuery] = useState("");
  const [activeTab, setActiveTab] = useState("dashboard");
  const [isDarkMode, setIsDarkMode] = useState(true);
  const [feedData, setFeedData] = useState<any[]>([]);
  const [showAbout, setShowAbout] = useState(false);

  // Enhanced App State
  const [currentView, setCurrentView] = useState("search");
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState<any>(null);
  const [searchResults, setSearchResults] = useState<any>(null);
  const [exportDataState, setExportDataState] = useState<any>(null);

  // Check auth on load
  useEffect(() => {
    const token = localStorage.getItem("token");
    if (token) setIsAuthenticated(true);
  }, []);

  // Theme toggle
  const toggleTheme = () => {
    setIsDarkMode((prev) => !prev);
    document.body.classList.toggle("light-mode");
  };

  // Clear threat feed cache
  const clearFeedCache = () => {
    setFeedData([]);
    alert("Threat Feed cache cleared!");
  };

  // Export data
  const exportData = () => {
    const torResults = localStorage.getItem("latestTorResults");
    const parsedResults = torResults ? JSON.parse(torResults) : null;

    if (!parsedResults) {
      alert("No search results to export. Please browse a website first.");
      return;
    }

    const data = {
      exportMetadata: {
        exportTimestamp: new Date().toISOString(),
        searchKeyword: parsedResults.keyword,
        targetWebsite: parsedResults.url,
        dataExtractionType: "COMPLETE_WEBSITE_CRAWL",
        totalDataPoints: parsedResults.completeWebsiteData
          ? parsedResults.completeWebsiteData.content.posts.length +
            parsedResults.completeWebsiteData.content.userProfiles.length +
            parsedResults.completeWebsiteData.content.messages.length +
            parsedResults.completeWebsiteData.content.listings.length
          : 0,
        exportNote:
          "COMPLETE website extraction - ALL posts, comments, users, messages, listings, chats",
      },
      searchResults: parsedResults
        ? {
            url: parsedResults.url,
            keyword: parsedResults.keyword,
            keywordFound: parsedResults.keywordFound,
            keywordCount: parsedResults.keywordCount,
            title: parsedResults.title,
            mode: parsedResults.mode,
            stats: parsedResults.stats,
            searchTimestamp: new Date().toISOString(),
          }
        : "No Tor search results available",
      completeWebsiteData: parsedResults.completeWebsiteData || {
        error: "No complete data available",
      },
      allExtractedContent: {
        fullWebsiteText: parsedResults.fullContent,
        totalCharacters: parsedResults.fullContentLength,
        allPosts: parsedResults.completeWebsiteData?.content.posts || [],
        allUserProfiles:
          parsedResults.completeWebsiteData?.content.userProfiles || [],
        allMessages: parsedResults.completeWebsiteData?.content.messages || [],
        allListings: parsedResults.completeWebsiteData?.content.listings || [],
        websiteStructure: parsedResults.completeWebsiteData?.structure || {},
        keywordAnalysis:
          parsedResults.completeWebsiteData?.keywordMatches || {},
      },
      threats: feedData.length ? feedData : ["No cached threats available"],
    };

    const blob = new Blob([JSON.stringify(data, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `complete_crawl_${
      parsedResults.keyword || "data"
    }_${parsedResults.url.replace(/[^a-zA-Z0-9]/g, "_")}_${
      new Date().getTime()
    }.json`;
    a.click();
    URL.revokeObjectURL(url);

    alert(
      `✅ COMPLETE DATA EXPORTED!\n\nWebsite: ${parsedResults.url}\nKeyword: ${parsedResults.keyword}\nTotal Posts: ${
        parsedResults.stats?.postsFound || 0
      }\nTotal Users: ${parsedResults.stats?.usersFound || 0}\nTotal Messages: ${
        parsedResults.stats?.messagesFound || 0
      }\nTotal Listings: ${parsedResults.stats?.listingsFound || 0}`
    );
  };

  // Dashboard content
  const renderContent = () => {
    if (activeTab === "dashboard") {
      return (
        <>
          <Metrics />
          <TorCrawler query={query} />
          <div className="content-row">
            <div className="column left-col">
              <ThreatFeed query={query} />
              <CaseManagement />
              <Watchlist />
            </div>
            <div className="column right-col">
              <ActorProfiles />
              <GeoMap />
              <DataFlow />
              <ActivityTimeline />
            </div>
          </div>
        </>
      );
    }

    if (activeTab === "threats") return <ThreatFeed query={query} />;
    if (activeTab === "actors") return <ActorProfiles />;
    if (activeTab === "markets")
      return (
        <>
          <Watchlist />
          <CaseManagement />
        </>
      );
    if (activeTab === "reports")
      return (
        <>
          <Metrics />
          <DataFlow />
        </>
      );
    if (activeTab === "settings")
      return (
        <section className="panel">
          <h3>⚙️ Settings</h3>
          <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
            <button
              onClick={toggleTheme}
              style={{
                padding: "10px",
                borderRadius: "6px",
                cursor: "pointer",
              }}
            >
              {isDarkMode ? "🌗 Switch to Light Mode" : "🌑 Switch to Dark Mode"}
            </button>
            <button
              onClick={clearFeedCache}
              style={{
                padding: "10px",
                borderRadius: "6px",
                cursor: "pointer",
              }}
            >
              🗑️ Clear Threat Feed Cache
            </button>
            <button
              onClick={exportData}
              style={{
                padding: "10px",
                borderRadius: "6px",
                cursor: "pointer",
                background: "#00ffc6",
                color: "#111822",
                fontWeight: "bold",
              }}
            >
              💾 EXPORT COMPLETE WEBSITE DATA
            </button>
            <button
              onClick={() => setShowAbout(!showAbout)}
              style={{
                padding: "10px",
                borderRadius: "6px",
                cursor: "pointer",
              }}
            >
              ℹ️ About App
            </button>
          </div>
          {showAbout && (
            <div
              style={{
                marginTop: "20px",
                padding: "12px",
                background: "rgba(255,255,255,0.05)",
                borderRadius: "8px",
              }}
            >
              <h4>ShadowSeeker Intelligence Console</h4>
              <p>
                Version: <strong>1.0</strong>
              </p>
              <p>Developed for cyber intelligence and threat monitoring.</p>
              <p>
                <strong>Made by: Samyak Jadhav</strong>
              </p>
            </div>
          )}
        </section>
      );

    return null;
  };

  // Login / Enhanced App
  const handleLogin = (userData: any) => {
    setIsAuthenticated(true);
    setUser(userData);
    localStorage.setItem("token", userData.token);
  };

  const handleLogout = () => {
    setIsAuthenticated(false);
    setUser(null);
    localStorage.removeItem("token");
  };

  if (!isAuthenticated) return <Login onLogin={handleLogin} />;

  return (
    <div className="dashboard">
      <Sidebar setActiveTab={setActiveTab} />
      <main className="main-content">
        <Topbar query={query} setQuery={setQuery} />
        {/* Dashboard main content */}
        {renderContent()}

        {/* Enhanced Views */}
        <div style={{ marginTop: "30px" }}>
          {currentView === "search" && (
            <>
              <AdvancedSearch onResults={setSearchResults} />
              {exportDataState && (
                <ExportManager
                  data={exportDataState}
                  recordCount={exportDataState.allMatches?.length || 0}
                />
              )}
            </>
          )}
          {currentView === "advanced" && <AdvancedSearch onResults={setSearchResults} />}
          {currentView === "alerts" && <AlertSystem />}
          {currentView === "dashboard" && <Dashboard user={user} />}
        </div>

        <footer className="app-footer">
          <div>© {new Date().getFullYear()} ShadowSeeker — Intelligence Console</div>
          <div className="footer-meta">Connected Sensors: 27 • Urgent Queue: 6</div>
        </footer>
      </main>
    </div>
  );
};

export default App;
