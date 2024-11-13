// SectionC.js
import React from 'react';
import './SectionC.css';

function SectionC({ onSelectItem }) {
  const handleSelectItem = (item) => {
    onSelectItem(item);
  };

  return (
    <div className="section-c">
      <div className="section-c1">Tìm kiếm</div>
      <div className="section-c2">
        <div onClick={() => handleSelectItem('Algorithm')}>Algorithm</div>
        <div onClick={() => handleSelectItem('Cryptosystem')}>Cryptosystem</div>
        <div onClick={() => handleSelectItem('DigitalSignature')}>Digital Signature</div>
      </div>
      <div className="section-c3">
        <h3>Blog</h3>
        <div>Hung</div>
        <div>Nguyen</div>
        <div>Manh</div>
      </div>
      <div className="section-c4">
        <h3>Social Media</h3>
        <div>GitHub Icon</div>
        <div>Facebook Icon</div>
      </div>
      <div className="section-c5">
        <h3>Support</h3>
        <a href="mailto:support@example.com">Gửi mail</a>
      </div>
    </div>
  );
}

export default SectionC;