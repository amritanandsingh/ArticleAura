import React from 'react';
import Button from './Button';
import Input from './Input';
import useForm from '../hooks/useForm';
import { loginValidation } from '../utils/validation';
import './AuthForms.css';

const LoginForm = ({ onSubmit, onForgotPassword, loading = false }) => {
  const {
    values,
    errors,
    touched,
    handleChange,
    handleBlur,
    handleSubmit,
  } = useForm({
    email: '',
    password: '',
    rememberMe: false,
  }, loginValidation);

  const onFormSubmit = async (formValues) => {
    if (onSubmit) {
      await onSubmit(formValues);
    }
  };

  return (
    <form 
      className="auth-form" 
      onSubmit={(e) => {
        e.preventDefault();
        handleSubmit(onFormSubmit);
      }}
      noValidate
    >
      <div className="auth-form__fields">
        <Input
          name="email"
          type="email"
          label="Email Address"
          placeholder="Enter your email"
          value={values.email}
          onChange={handleChange}
          onBlur={handleBlur}
          error={touched.email ? errors.email : ''}
          required
          disabled={loading}
          icon={
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/>
              <polyline points="22,6 12,13 2,6"/>
            </svg>
          }
        />

        <Input
          name="password"
          type="password"
          label="Password"
          placeholder="Enter your password"
          value={values.password}
          onChange={handleChange}
          onBlur={handleBlur}
          error={touched.password ? errors.password : ''}
          required
          disabled={loading}
        />

        <div className="auth-form__options">
          <label className="auth-form__checkbox">
            <input
              type="checkbox"
              name="rememberMe"
              checked={values.rememberMe}
              onChange={handleChange}
              disabled={loading}
            />
            <span className="auth-form__checkbox-custom"></span>
            <span className="auth-form__checkbox-label">Remember me</span>
          </label>

          <button
            type="button"
            className="auth-form__link"
            onClick={onForgotPassword}
            disabled={loading}
          >
            Forgot password?
          </button>
        </div>
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
        Sign In
      </Button>


    </form>
  );
};

export default LoginForm;