// FormComponent.js
import React, { useState, useEffect } from 'react';

function FormComponent({ formType, apiUrl, onBack }) {
  const [formData, setFormData] = useState({});
  const [apiResult, setApiResult] = useState(null);

  useEffect(() => {
    // Reset formData whenever formType changes
    setFormData({});
    setApiResult(null);
  }, [formType]);

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const response = await fetch(apiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData),
      });

      const data = await response.json();
      setApiResult(data);
    } catch (error) {
      console.error('Error:', error);
    }
  };

  const renderFormFields = () => {
    switch (formType) {
      case 'Create Key':
        return (
          <>
            <input
              type="text"
              name="keyName"
              value={formData.keyName || ''}
              onChange={handleInputChange}
              placeholder="Key Name"
            />
            <input
              type="text"
              name="keyLength"
              value={formData.keyLength || ''}
              onChange={handleInputChange}
              placeholder="Key Length"
            />
          </>
        );
      case 'Encrypt':
        return (
          <>
            <input
              type="text"
              name="data"
              value={formData.data || ''}
              onChange={handleInputChange}
              placeholder="Data to Encrypt"
            />
            <input
              type="text"
              name="encryptionKey"
              value={formData.encryptionKey || ''}
              onChange={handleInputChange}
              placeholder="Encryption Key"
            />
          </>
        );
      case 'Decode':
        return (
          <>
            <input
              type="text"
              name="encodedData"
              value={formData.encodedData || ''}
              onChange={handleInputChange}
              placeholder="Encoded Data"
            />
            <input
              type="text"
              name="decryptionKey"
              value={formData.decryptionKey || ''}
              onChange={handleInputChange}
              placeholder="Decryption Key"
            />
          </>
        );
      default:
        return null;
    }
  };

  return (
    <div>
      <h3>{formType}</h3>
      <form onSubmit={handleSubmit}>
        {renderFormFields()}
        <button type="submit">Submit</button>
      </form>
      <button onClick={onBack}>Back</button>
      {apiResult && (
        <div>
          <h4>API Result:</h4>
          <pre>{JSON.stringify(apiResult, null, 2)}</pre>
        </div>
      )}
    </div>
  );
}

export default FormComponent;