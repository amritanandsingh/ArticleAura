import React, { useState } from 'react';
import Button from './Button';
import Input from './Input';
import './AuthForms.css';

const VerifyForm = ({ email, onSubmit, onBack, loading = false }) => {
  const [code, setCode] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!code.trim()) {
      setError('Please enter the verification code.');
      return;
    }
    setError('');
    if (onSubmit) await onSubmit(code.trim());
  };

  return (
    <form className="auth-form" onSubmit={handleSubmit} noValidate>
      <div className="verify-form__info">
        <div className="verify-form__icon">
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/>
            <polyline points="22,6 12,13 2,6"/>
          </svg>
        </div>
        <p className="verify-form__message">
          We sent a 6-digit code to <strong>{email}</strong>. Enter it below to verify your account.
        </p>
      </div>

      <div className="auth-form__fields">
        <Input
          name="code"
          type="text"
          label="Verification Code"
          placeholder="Enter 6-digit code"
          value={code}
          onChange={(e) => setCode(e.target.value)}
          error={error}
          required
          disabled={loading}
          autoComplete="one-time-code"
        />
      </div>

      <Button
        type="submit"
        variant="primary"
        size="lg"
        fullWidth
        loading={loading}
        disabled={loading}
        className="auth-form__submit"
      >
        Verify Email
      </Button>

      <button
        type="button"
        className="auth-form__link"
        onClick={onBack}
        disabled={loading}
      >
        ← Back to Sign Up
      </button>
    </form>
  );
};

export default VerifyForm;
