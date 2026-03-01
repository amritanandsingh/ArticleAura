import React from 'react';
import { useNavigate } from 'react-router-dom';
import Card from './Card';
import Button from './Button';
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
