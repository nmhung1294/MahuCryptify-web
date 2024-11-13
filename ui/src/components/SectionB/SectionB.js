// SectionB.js
import React, { useState, useEffect } from 'react';
import './SectionB.css';
import FormComponent from './FormComponent';
function SectionB({selectedItem, selectedSubItem, setSelectedSubItem, resetSelection}) {

  const renderSubItemContent = () => {
    if (!selectedSubItem) return null;

    return (
      <div>
        <h3>{selectedSubItem}</h3>
        <ul>
          <li onClick={() => setSelectedSubItem('Create Key')}>Create Key</li>
          <li onClick={() => setSelectedSubItem('Encrypt')}>Encrypt</li>
          <li onClick={() => setSelectedSubItem('Decode')}>Decode</li>
        </ul>
      </div>
    );
  };

  const renderSelectedContent = () => {
    if (!selectedItem) {
      return <div>Trang trống màu xanh</div>;
    }

    if (selectedItem === 'Algorithm') {
      return (
        <div>
          <h2>Algorithms</h2>
          <ul>
            {Array.from({ length: 50 }, (_, i) => (
              <li key={i} onClick={() => setSelectedSubItem(`Algo${i + 1}`)}>
                Algo{i + 1}
              </li>
            ))}
          </ul>
          {renderSubItemContent()}
          <button onClick={resetSelection}>Back to Main</button>
        </div>
      );
    }

    if (selectedItem === 'Cryptosystem') {
      return (
        <div>
          <h2>Cryptography Systems</h2>
          <ul>
            {Array.from({ length: 30 }, (_, i) => (
              <li key={i} onClick={() => setSelectedSubItem(`Crypto${i + 1}`)}>
                Crypto{i + 1}
              </li>
            ))}
          </ul>
          {renderSubItemContent()}
        </div>
      );
    }

    if (selectedItem === 'DigitalSignature') {
      return (
        <div>
          <h2>Digital Signature</h2>
          <ul>
            {Array.from({ length: 20 }, (_, i) => (
              <li key={i} onClick={() => setSelectedSubItem(`Signature${i + 1}`)}>
                Signature{i + 1}
              </li>
            ))}
          </ul>
          {renderSubItemContent()}
        </div>
      );
    }

    if (selectedItem.startsWith('Blog')) {
      return (
        <div>
          <h2>{selectedItem}</h2>
          <p>Chi tiết cho {selectedItem}</p>
        </div>
      );
    }

    return <div>Chi tiết cho {selectedItem}</div>;
  };

  
  const renderContent = () => {
    if (!selectedItem) {
      return <div>Trang trống màu xanh</div>;
    }
    
    switch (selectedSubItem) {
        case 'Create Key':
          return (
            <FormComponent
              formType="Create Key"
              apiUrl="http://127.0.0.1:8000/api/create-key/"
              onBack={() => setSelectedSubItem(null)}
            />
          );
        case 'Encrypt':
          return (
            <FormComponent
              formType="Encrypt"
              apiUrl="http://127.0.0.1:8000/api/encrypt/"
              onBack={() => setSelectedSubItem(null)}
            />
          );
        case 'Decode':
          return (
            <FormComponent
              formType="Decode"
              apiUrl="http://127.0.0.1:8000/api/decode/"
              onBack={() => setSelectedSubItem(null)}
            />
          );
        default:
          return renderSelectedContent();
    }
  };
  return (
    <div className="section-b">
      {renderContent()}
    </div>
  );
}

export default SectionB;