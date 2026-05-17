import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Card from './Card';
import Button from './Button';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext';
import { getSession } from '../services/cognitoService';
import './HomePage.css';

const HomePage = () => {
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const { showToast } = useToast();

  const firstName = user?.given_name || '';
  const lastName = user?.family_name || '';
  const fullName = [firstName, lastName].filter(Boolean).join(' ') || 'User';
  const email = user?.email || '';
  const initials = [firstName[0], lastName[0]].filter(Boolean).join('').toUpperCase() || 'U';

  const [workflows, setWorkflows] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!email) return;

    const fetchWorkflows = async () => {
      const apiUrl = process.env.REACT_APP_HOME_PAGE_URL;
      if (!apiUrl) {
        setError('Workflow API URL is not configured.');
        return;
      }

      setLoading(true);
      setError(null);

      try {
        const { session } = await getSession();
        const token = session?.getIdToken()?.getJwtToken();
        const url = `${apiUrl}${apiUrl.includes('?') ? '&' : '?'}email=${encodeURIComponent(email)}`;

        const response = await fetch(url, {
          headers: {
            ...(token ? { Authorization: `Bearer ${token}` } : {}),
            'Content-Type': 'application/json',
          },
        });

        if (!response.ok) {
          throw new Error(`Workflow request failed (${response.status})`);
        }

        const data = await response.json();
        if (!data.success) {
          throw new Error(data.message || 'Failed to load workflows.');
        }

        setWorkflows(Array.isArray(data.workflows) ? data.workflows : []);
      } catch (err) {
        setError(err?.message || 'Unable to load workflows.');
      } finally {
        setLoading(false);
      }
    };

    fetchWorkflows();
  }, [email]);

  const handleSignOut = () => {
    logout();
    showToast('You have been signed out.', 'info');
    navigate('/');
  };

  return (
    <div className="home-page">
      <div className="home-page__container">
        {/* Header */}
        <div className="home-page__header animate-slideIn">
          <div className="auth-page__logo">
            <div className="auth-page__logo-icon">
              <svg width="40" height="40" viewBox="0 0 40 40" fill="none">
                <rect width="40" height="40" rx="12" fill="url(#gradient1)"/>
                <path d="M12 16h16M12 20h16M12 24h10" stroke="white" strokeWidth="2" strokeLinecap="round"/>
                <defs>
                  <linearGradient id="gradient1" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" stopColor="#667eea"/>
                    <stop offset="100%" stopColor="#764ba2"/>
                  </linearGradient>
                </defs>
              </svg>
            </div>
            <h1 className="auth-page__logo-text">ArticleAura</h1>
          </div>
        </div>

        {/* Welcome Card */}
        <Card variant="strong" size="lg" className="home-page__card animate-scaleIn">
          <div className="home-page__welcome">
            <div className="home-page__avatar">{initials}</div>
            <div className="home-page__greeting">
              <h2 className="home-page__name">Welcome, {fullName}!</h2>
              <p className="home-page__subtitle">You are signed in to ArticleAura</p>
            </div>
          </div>

          <div className="home-page__info">
            <div className="home-page__info-item">
              <span className="home-page__info-label">Full Name</span>
              <span className="home-page__info-value">{fullName}</span>
            </div>
            <div className="home-page__info-item">
              <span className="home-page__info-label">Email Address</span>
              <span className="home-page__info-value">{email}</span>
            </div>
          </div>

          <Button
            variant="outline"
            size="md"
            onClick={handleSignOut}
            className="home-page__signout"
          >
            Sign Out
          </Button>
        </Card>

        <section className="home-page__workflow-section animate-slideIn">
          <div className="home-page__workflow-header">
            <h2>My Workflows</h2>
            <p>Workflows associated with {email || 'your account'}.</p>
          </div>

          {loading && <div className="home-page__status">Loading workflows…</div>}
          {error && <div className="home-page__error">Error: {error}</div>}
          {!loading && !error && workflows.length === 0 && (
            <div className="home-page__empty">No workflows found for this account.</div>
          )}

          <div className="home-page__workflow-list">
            {workflows.map((workflow) => (
              <article key={workflow.id} className="home-page__workflow-card">
                <div className="home-page__workflow-card-header">
                  <h3>{workflow.name}</h3>
                  <span className={`home-page__workflow-status home-page__workflow-status--${workflow.status?.toLowerCase()}`}>
                    {workflow.status}
                  </span>
                </div>
                <p className="home-page__workflow-summary">{workflow.summary}</p>
                <div className="home-page__workflow-meta">
                  <span>{workflow.category}</span>
                  <span>{workflow.createdAt ? new Date(workflow.createdAt).toLocaleString() : ''}</span>
                </div>
                {Array.isArray(workflow.promptSteps) && workflow.promptSteps.length > 0 && (
                  <div className="home-page__workflow-steps">
                    <strong>Prompt Steps</strong>
                    <ol>
                      {workflow.promptSteps.map((step, index) => (
                        <li key={index}>{step}</li>
                      ))}
                    </ol>
                  </div>
                )}
              </article>
            ))}
          </div>
        </section>

        {/* Background decorations */}
        <div className="auth-page__bg">
          <div className="auth-page__bg-circle auth-page__bg-circle--1 animate-float"></div>
          <div className="auth-page__bg-circle auth-page__bg-circle--2 animate-float"></div>
          <div className="auth-page__bg-gradient auth-page__bg-gradient--1"></div>
          <div className="auth-page__bg-gradient auth-page__bg-gradient--2"></div>
        </div>
      </div>
    </div>
  );
};

export default HomePage;
