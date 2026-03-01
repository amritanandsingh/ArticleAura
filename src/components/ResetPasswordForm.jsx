import React, { useState } from 'react';
import Button from './Button';
import Input from './Input';
import './AuthForms.css';

const ResetPasswordForm = ({ email, onSubmit, onBack, loading = false }) => {
  const [code, setCode] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [errors, setErrors] = useState({});

  const validate = () => {
    const errs = {};
    if (!code.trim()) errs.code = 'Please enter the reset code.';
    if (!password) errs.password = 'Password is required.';
    else if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$/.test(password))
      errs.password = 'At least 8 characters with uppercase, lowercase, and number.';
    if (!confirmPassword) errs.confirmPassword = 'Please confirm your password.';
    else if (password !== confirmPassword) errs.confirmPassword = 'Passwords do not match.';
    return errs;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const errs = validate();
    setErrors(errs);
    if (Object.keys(errs).length > 0) return;
    if (onSubmit) await onSubmit(code.trim(), password);
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
          We sent a reset code to <strong>{email}</strong>. Enter the code and your new password below.
        </p>
      </div>

      <div className="auth-form__fields">
        <Input
          name="code"
          type="text"
          label="Reset Code"
          placeholder="Enter the code from your email"
          value={code}
          onChange={(e) => setCode(e.target.value)}
          error={errors.code}
          required
          disabled={loading}
          autoComplete="one-time-code"
        />

        <Input
          name="password"
          type="password"
          label="New Password"
          placeholder="Create a new password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          error={errors.password}
          required
          disabled={loading}
          helperText="At least 8 characters with uppercase, lowercase, and number"
        />

        <Input
          name="confirmPassword"
          type="password"
          label="Confirm New Password"
          placeholder="Confirm your new password"
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
          error={errors.confirmPassword}
          required
          disabled={loading}
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
        Reset Password
      </Button>

      <button type="button" className="auth-form__link" onClick={onBack} disabled={loading}>
        ← Back
      </button>
    </form>
  );
};

export default ResetPasswordForm;
