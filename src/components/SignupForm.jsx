import React from 'react';
import Button from './Button';
import Input from './Input';
import useForm from '../hooks/useForm';
import { signupValidation } from '../utils/validation';
import './AuthForms.css';

const SignupForm = ({ onSubmit, loading = false }) => {
  const {
    values,
    errors,
    touched,
    handleChange,
    handleBlur,
    handleSubmit,
  } = useForm({
    firstName: '',
    lastName: '',
    email: '',
    password: '',
    confirmPassword: '',
    acceptTerms: false,
  }, signupValidation);

  const onFormSubmit = async (formValues) => {
    if (!formValues.acceptTerms) {
      return;
    }
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
        <div className="auth-form__row">
          <Input
            name="firstName"
            type="text"
            label="First Name"
            placeholder="John"
            value={values.firstName}
            onChange={handleChange}
            onBlur={handleBlur}
            error={touched.firstName ? errors.firstName : ''}
            required
            disabled={loading}
          />
          
          <Input
            name="lastName"
            type="text"
            label="Last Name"
            placeholder="Doe"
            value={values.lastName}
            onChange={handleChange}
            onBlur={handleBlur}
            error={touched.lastName ? errors.lastName : ''}
            required
            disabled={loading}
          />
        </div>

        <Input
          name="email"
          type="email"
          label="Email Address"
          placeholder="john.doe@example.com"
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
          placeholder="Create a secure password"
          value={values.password}
          onChange={handleChange}
          onBlur={handleBlur}
          error={touched.password ? errors.password : ''}
          required
          disabled={loading}
          helperText="At least 8 characters with uppercase, lowercase, and number"
        />

        <Input
          name="confirmPassword"
          type="password"
          label="Confirm Password"
          placeholder="Confirm your password"
          value={values.confirmPassword}
          onChange={handleChange}
          onBlur={handleBlur}
          error={touched.confirmPassword ? errors.confirmPassword : ''}
          required
          disabled={loading}
        />

        <div className="auth-form__terms">
          <label className="auth-form__checkbox">
            <input
              type="checkbox"
              name="acceptTerms"
              checked={values.acceptTerms}
              onChange={handleChange}
              disabled={loading}
            />
            <span className="auth-form__checkbox-custom"></span>
            <span className="auth-form__checkbox-label">
              I accept the{' '}
              <a href="#" className="auth-form__link-inline">
                Terms of Service
              </a>{' '}
              and{' '}
              <a href="#" className="auth-form__link-inline">
                Privacy Policy
              </a>
            </span>
          </label>
          
          {!values.acceptTerms && touched.confirmPassword && (
            <div className="auth-form__terms-error">
              Please accept the terms and conditions
            </div>
          )}
        </div>
      </div>

      <Button
        type="submit"
        variant="primary"
        size="lg"
        fullWidth
        loading={loading}
        disabled={loading || !values.acceptTerms}
        className="auth-form__submit"
      >
        Create Account
      </Button>
    </form>
  );
};

export default SignupForm;