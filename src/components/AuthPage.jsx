import React, { useState } from 'react';
import { useNavigate, Navigate } from 'react-router-dom';
import Card from './Card';
import LoginForm from './LoginForm';
import SignupForm from './SignupForm';
import VerifyForm from './VerifyForm';
import ForgotPasswordForm from './ForgotPasswordForm';
import ResetPasswordForm from './ResetPasswordForm';
import './AuthPage.css';
import { signIn, signUp, confirmSignUp, forgotPassword, resetPassword } from '../services/cognitoService';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext';

const AuthPage = () => {
  const navigate = useNavigate();
  const { login, isAuthenticated, isLoading: authLoading } = useAuth();
  const { showToast } = useToast();

  const [activeTab, setActiveTab] = useState('login');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [pendingEmail, setPendingEmail] = useState('');
  const [resetEmail, setResetEmail] = useState('');

  if (authLoading) {
    return (
      <div className="loading-screen">
        <div className="loading-screen__spinner"></div>
      </div>
    );
  }

  if (isAuthenticated) {
    return <Navigate to="/home" replace />;
  }

  const handleLogin = async (credentials) => {
    setIsSubmitting(true);
    try {
      const { user } = await signIn(credentials.email, credentials.password);
      login(user);
      navigate('/home');
    } catch (error) {
      showToast(error.message || 'Login failed. Please try again.', 'error');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleSignup = async (userData) => {
    setIsSubmitting(true);
    try {
      await signUp(userData.email, userData.password, userData.firstName, userData.lastName);
      setPendingEmail(userData.email);
      setActiveTab('verify');
    } catch (error) {
      showToast(error.message || 'Signup failed. Please try again.', 'error');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleVerify = async (code) => {
    setIsSubmitting(true);
    try {
      await confirmSignUp(pendingEmail, code);
      showToast('Email verified! You can now sign in.', 'success');
      setPendingEmail('');
      setActiveTab('login');
    } catch (error) {
      showToast(error.message || 'Verification failed. Please try again.', 'error');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleForgotPassword = async (email) => {
    setIsSubmitting(true);
    try {
      await forgotPassword(email);
      setResetEmail(email);
      setActiveTab('reset');
    } catch (error) {
      showToast(error.message || 'Could not send reset code. Please try again.', 'error');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleResetPassword = async (code, newPassword) => {
    setIsSubmitting(true);
    try {
      await resetPassword(resetEmail, code, newPassword);
      showToast('Password reset successful! You can now sign in.', 'success');
      setResetEmail('');
      setActiveTab('login');
    } catch (error) {
      showToast(error.message || 'Password reset failed. Please try again.', 'error');
    } finally {
      setIsSubmitting(false);
    }
  };

  const subtitleMap = {
    login: 'Welcome back! Sign in to your account.',
    signup: 'Create your account to get started.',
    verify: 'Check your email for the verification code.',
    forgot: 'Reset your password.',
    reset: 'Enter the code and your new password.',
  };

  const isOverlayTab = activeTab === 'verify' || activeTab === 'forgot' || activeTab === 'reset';

  return (
    <div className="auth-page">
      <div className="auth-page__container">
        {/* Header */}
        <div className="auth-page__header">
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
          <p className="auth-page__subtitle">{subtitleMap[activeTab]}</p>
        </div>

        {/* Auth Card */}
        <Card variant="strong" size="lg" className="auth-page__card animate-scaleIn">
          {/* Tab Navigation */}
          {!isOverlayTab && (
            <div className="auth-tabs">
              <button
                className={`auth-tabs__tab ${activeTab === 'login' ? 'auth-tabs__tab--active' : ''}`}
                onClick={() => setActiveTab('login')}
                disabled={isSubmitting}
              >
                Sign In
              </button>
              <button
                className={`auth-tabs__tab ${activeTab === 'signup' ? 'auth-tabs__tab--active' : ''}`}
                onClick={() => setActiveTab('signup')}
                disabled={isSubmitting}
              >
                Sign Up
              </button>
              <div
                className="auth-tabs__indicator"
                style={{ transform: `translateX(${activeTab === 'login' ? '0%' : '100%'})` }}
              />
            </div>
          )}

          {/* Form Content */}
          <div className="auth-content">
            <div className="auth-content__form">
              {activeTab === 'login' && (
                <LoginForm
                  onSubmit={handleLogin}
                  onForgotPassword={() => setActiveTab('forgot')}
                  loading={isSubmitting}
                />
              )}
              {activeTab === 'signup' && (
                <SignupForm onSubmit={handleSignup} loading={isSubmitting} />
              )}
              {activeTab === 'verify' && (
                <VerifyForm
                  email={pendingEmail}
                  onSubmit={handleVerify}
                  onBack={() => setActiveTab('signup')}
                  loading={isSubmitting}
                />
              )}
              {activeTab === 'forgot' && (
                <ForgotPasswordForm
                  onSubmit={handleForgotPassword}
                  onBack={() => setActiveTab('login')}
                  loading={isSubmitting}
                />
              )}
              {activeTab === 'reset' && (
                <ResetPasswordForm
                  email={resetEmail}
                  onSubmit={handleResetPassword}
                  onBack={() => setActiveTab('forgot')}
                  loading={isSubmitting}
                />
              )}
            </div>
          </div>

        </Card>

        {/* Footer */}
        <div className="auth-page__footer">
          <p>© 2026 ArticleAura. All rights reserved.</p>
          <div className="auth-page__footer-links">
            <a href="#" className="auth-page__footer-link">Privacy Policy</a>
            <a href="#" className="auth-page__footer-link">Terms of Service</a>
            <a href="#" className="auth-page__footer-link">Help</a>
          </div>
        </div>
      </div>

      {/* Background Decorations */}
      <div className="auth-page__bg">
        <div className="auth-page__bg-circle auth-page__bg-circle--1 animate-float"></div>
        <div className="auth-page__bg-circle auth-page__bg-circle--2 animate-float"></div>
        <div className="auth-page__bg-circle auth-page__bg-circle--3 animate-float"></div>
        <div className="auth-page__bg-gradient auth-page__bg-gradient--1"></div>
        <div className="auth-page__bg-gradient auth-page__bg-gradient--2"></div>
      </div>
    </div>
  );
};

export default AuthPage;
