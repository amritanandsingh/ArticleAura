import React, { useState } from "react";
import "./App.css";

function App() {
  const [count, setCount] = useState(0);
  const [message, setMessage] = useState("Welcome to ArticleAura!");

  const handleIncrement = () => {
    setCount(count + 1);
  };

  const handleDecrement = () => {
    setCount(count - 1);
  };

  const handleReset = () => {
    setCount(0);
  };

  const handleMessageChange = (e) => {
    setMessage(e.target.value);
  };

  return (
    <div className="App">
      <header className="App-header">
        <h1>ArticleAura</h1>
        <p className="subtitle">A Simple React Web Page</p>

        <div className="welcome-section">
          <h2>Welcome Message</h2>
          <input
            type="text"
            value={message}
            onChange={handleMessageChange}
            className="message-input"
            placeholder="Enter your message..."
          />
          <p className="display-message">{message}</p>
        </div>

        <div className="counter-section">
          <h2>Interactive Counter</h2>
          <div className="counter-display">
            <span className="count-number">{count}</span>
          </div>
          <div className="button-group">
            <button onClick={handleDecrement} className="btn btn-decrement">
              -
            </button>
            <button onClick={handleReset} className="btn btn-reset">
              Reset
            </button>
            <button onClick={handleIncrement} className="btn btn-increment">
              +
            </button>
          </div>
        </div>

        <div className="features-section">
          <h2>Features</h2>
          <div className="features-grid">
            <div className="feature-card">
              <h3>⚛️ React 18</h3>
              <p>Built with the latest React features</p>
            </div>
            <div className="feature-card">
              <h3>🎨 Modern UI</h3>
              <p>Beautiful gradient design</p>
            </div>
            <div className="feature-card">
              <h3>📱 Responsive</h3>
              <p>Works on all devices</p>
            </div>
            <div className="feature-card">
              <h3>⚡ Fast</h3>
              <p>Optimized performance</p>
            </div>
          </div>
        </div>

        <footer className="App-footer">
          <p>Built with ❤️ using React</p>
        </footer>
      </header>
    </div>
  );
}

export default App;
