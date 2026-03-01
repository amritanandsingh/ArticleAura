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

          {/* Social Login */}
          {!isOverlayTab && (
            <div className="auth-social">
              <div className="auth-social__divider">
                <span>or continue with</span>
              </div>
              <div className="auth-social__buttons">
                <button className="auth-social__button" disabled={isSubmitting}>
                  <svg width="20" height="20" viewBox="0 0 24 24">
                    <path fill="currentColor" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                    <path fill="currentColor" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                    <path fill="currentColor" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                    <path fill="currentColor" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                  </svg>
                  Google
                </button>
                <button className="auth-social__button" disabled={isSubmitting}>
                  <svg width="20" height="20" viewBox="0 0 24 24">
                    <path fill="currentColor" d="M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.47h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.47h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z"/>
                  </svg>
                  Facebook
                </button>
              </div>
            </div>
          )}
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
