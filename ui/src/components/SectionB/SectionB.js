// SectionB.js
import React, { useState, useEffect } from 'react';
import './SectionB.css';
import FormComponent from './FormComponent';

function SectionB({ selectedItem, selectedSubItem, setSelectedSubItem, resetSelection }) {
  const [cryptosystemType, setCryptosystemType] = useState(null);
  const [previousSubItem, setPreviousSubItem] = useState(null);

  const renderSubItemContent = () => {
    if (!selectedSubItem) return null;

    return (
      <div>
        <h3>{selectedSubItem}</h3>
        <ul>
          <li onClick={() => {
            setPreviousSubItem(selectedSubItem);
            setSelectedSubItem('Create Key');
          }}>Create Key</li>
          <li onClick={() => {
            setPreviousSubItem(selectedSubItem);
            setSelectedSubItem('Encrypt');
          }}>Encrypt</li>
          <li onClick={() => {
            setPreviousSubItem(selectedSubItem);
            setSelectedSubItem('Decode');
          }}>Decode</li>
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
            {Array.from({ length: 3 }, (_, i) => (
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
            {Array.from({ length: 2 }, (_, i) => (
              <li key={i} onClick={() => {
                setSelectedSubItem(`Crypto${i + 1}`);
                setCryptosystemType(`Crypto${i + 1}`);
              }}>
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
            {Array.from({ length: 3 }, (_, i) => (
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
      case 'Encrypt':
      case 'Decode':
        return (
          <FormComponent
            formType={selectedSubItem}
            cryptosystemType={cryptosystemType}
            apiUrl={`http://127.0.0.1:8000/api/${cryptosystemType?.toLowerCase()}/${selectedSubItem.toLowerCase()}/`}
            onBack={() => setSelectedSubItem(previousSubItem)}
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