import React from 'react';
import { useNavigate } from 'react-router-dom';
import Button from './Button';
import WorkflowManager from './workflows/WorkflowManager';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext';
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

  const handleSignOut = () => {
    logout();
    showToast('You have been signed out.', 'info');
    navigate('/');
  };

  return (
    <div className="home-page">
      <header className="home-page__nav animate-slideIn">
        <div className="home-page__nav-inner">
          <div className="home-page__nav-brand">
            <div className="auth-page__logo-icon">
              <svg width="36" height="36" viewBox="0 0 40 40" fill="none">
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
            <span className="home-page__nav-brand-text">ArticleAura</span>
          </div>

          <div className="home-page__nav-user">
            <div className="home-page__nav-avatar" aria-hidden="true">{initials}</div>
            <div className="home-page__nav-identity">
              <span className="home-page__nav-name">{fullName}</span>
              <span className="home-page__nav-email">{email}</span>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={handleSignOut}
              className="home-page__nav-signout"
            >
              Sign Out
            </Button>
          </div>
        </div>
      </header>

      <main className="home-page__container">
        <div className="home-page__welcome-strip animate-scaleIn">
          <h1 className="home-page__welcome-title">
            Welcome back, {firstName || 'there'}
          </h1>
          <p className="home-page__welcome-subtitle">
            Manage the workflows linked to {email || 'your account'}.
          </p>
        </div>

        <WorkflowManager email={email} />
      </main>

      <div className="auth-page__bg">
        <div className="auth-page__bg-circle auth-page__bg-circle--1 animate-float"></div>
        <div className="auth-page__bg-circle auth-page__bg-circle--2 animate-float"></div>
        <div className="auth-page__bg-gradient auth-page__bg-gradient--1"></div>
        <div className="auth-page__bg-gradient auth-page__bg-gradient--2"></div>
      </div>
    </div>
  );
};

export default HomePage;
