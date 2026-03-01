import React from 'react';
import './Card.css';

const Card = ({
  children,
  variant = 'default',
  size = 'md',
  hover = false,
  className = '',
  ...props
}) => {
  const cardClass = [
    'card',
    `card--${variant}`,
    `card--${size}`,
    hover ? 'card--hover' : '',
    className
  ].filter(Boolean).join(' ');

  return (
    <div className={cardClass} {...props}>
      {children}
    </div>
  );
};

export default Card;