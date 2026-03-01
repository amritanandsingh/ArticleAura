import React, { useState, forwardRef } from 'react';
import './Input.css';

const Input = forwardRef(({
  label,
  type = 'text',
  placeholder,
  error,
  helperText,
  required = false,
  disabled = false,
  size = 'md',
  icon,
  showPassword = false,
  className = '',
  ...props
}, ref) => {
  const [showPasswordToggle, setShowPasswordToggle] = useState(false);
  const [inputType, setInputType] = useState(type);

  const handlePasswordToggle = () => {
    if (type === 'password') {
      setShowPasswordToggle(!showPasswordToggle);
      setInputType(showPasswordToggle ? 'password' : 'text');
    }
  };

  const inputId = `input-${Math.random().toString(36).substr(2, 9)}`;
  
  const inputClass = [
    'input',
    `input--${size}`,
    error ? 'input--error' : '',
    disabled ? 'input--disabled' : '',
    icon ? 'input--with-icon' : '',
    className
  ].filter(Boolean).join(' ');

  const containerClass = [
    'input-container',
    disabled ? 'input-container--disabled' : ''
  ].filter(Boolean).join(' ');

  return (
    <div className={containerClass}>
      {label && (
        <label htmlFor={inputId} className="input__label">
          {label}
          {required && <span className="input__required">*</span>}
        </label>
      )}
      
      <div className="input__wrapper">
        {icon && (
          <div className="input__icon input__icon--left">
            {icon}
          </div>
        )}
        
        <input
          ref={ref}
          id={inputId}
          type={inputType}
          className={inputClass}
          placeholder={placeholder}
          disabled={disabled}
          {...props}
        />
        
        {type === 'password' && (
          <button
            type="button"
            className="input__icon input__icon--right input__password-toggle"
            onClick={handlePasswordToggle}
            disabled={disabled}
            aria-label={showPasswordToggle ? 'Hide password' : 'Show password'}
          >
            {showPasswordToggle ? (
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
                <line x1="1" y1="1" x2="23" y2="23"/>
              </svg>
            ) : (
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                <circle cx="12" cy="12" r="3"/>
              </svg>
            )}
          </button>
        )}
      </div>
      
      {error && (
        <div className="input__error">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="12" cy="12" r="10"/>
            <line x1="15" y1="9" x2="9" y2="15"/>
            <line x1="9" y1="9" x2="15" y2="15"/>
          </svg>
          {error}
        </div>
      )}
      
      {helperText && !error && (
        <div className="input__helper">
          {helperText}
        </div>
      )}
    </div>
  );
});

Input.displayName = 'Input';

export default Input;