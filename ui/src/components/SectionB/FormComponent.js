import React, { useState, useEffect } from 'react';

function FormComponent({ formType, cryptosystemType, apiUrl, onBack }) {
  const [formData, setFormData] = useState({});
  const [apiResult, setApiResult] = useState(null);

  useEffect(() => {
    // Reset formData whenever formType or cryptosystemType changes
    setFormData({});
    setApiResult(null);
  }, [formType, cryptosystemType]);

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
    if (!cryptosystemType) return null;

    switch (cryptosystemType) {
      case 'RSA':
        if (formType === 'Create Key') {
          return (
            <>
              <input
                type="number"
                name="bits"
                value={formData.bits || ''}
                onChange={handleInputChange}
                placeholder="Enter Number of bits of prime number"
              />
            </>
          );
        } else if (formType === 'Encrypt') {
          return (
            <>
              <input
                type="text"
                name="data"
                value={formData.data || ''}
                onChange={handleInputChange}
                placeholder="Data to Encrypt for Crypto1"
              />
              <input
                type="text"
                name="encryptionKey"
                value={formData.encryptionKey || ''}
                onChange={handleInputChange}
                placeholder="Encryption Key for Crypto1"
              />
            </>
          );
        } else if (formType === 'Decode') {
          return (
            <>
              <input
                type="text"
                name="encodedData"
                value={formData.encodedData || ''}
                onChange={handleInputChange}
                placeholder="Encoded Data for Crypto1"
              />
              <input
                type="text"
                name="decryptionKey"
                value={formData.decryptionKey || ''}
                onChange={handleInputChange}
                placeholder="Decryption Key for Crypto1"
              />
            </>
          );
        }
        break;
      case 'ElGamal':
        if (formType === 'Create Key') {
          return (
            <>
              <input
                type="text"
                name="keyName"
                value={formData.keyName || ''}
                onChange={handleInputChange}
                placeholder="Key Name for Crypto2"
              />
              <input
                type="text"
                name="keyType"
                value={formData.keyType || ''}
                onChange={handleInputChange}
                placeholder="Key Type for Crypto2"
              />
            </>
          );
        } else if (formType === 'Encrypt') {
          return (
            <>
              <input
                type="text"
                name="data"
                value={formData.data || ''}
                onChange={handleInputChange}
                placeholder="Data to Encrypt for Crypto2"
              />
              <input
                type="text"
                name="encryptionKey"
                value={formData.encryptionKey || ''}
                onChange={handleInputChange}
                placeholder="Encryption Key for Crypto2"
              />
            </>
          );
        } else if (formType === 'Decode') {
          return (
            <>
              <input
                type="text"
                name="encodedData"
                value={formData.encodedData || ''}
                onChange={handleInputChange}
                placeholder="Encoded Data for Crypto2"
              />
              <input
                type="text"
                name="decryptionKey"
                value={formData.decryptionKey || ''}
                onChange={handleInputChange}
                placeholder="Decryption Key for Crypto2"
              />
            </>
          );
        }
        break;
      case 'Elliptic Curve':
        if (formType === 'Create Key') {
          return (
            <>
              <input
                type="text"
                name="keyName"
                value={formData.keyName || ''}
                onChange={handleInputChange}
                placeholder="Key Name for Crypto3"
              />
              <input
                type="text"
                name="keyType"
                value={formData.keyType || ''}
                onChange={handleInputChange}
                placeholder="Key Type for Crypto3"
              />
            </>
          );
        } else if (formType === 'Encrypt') {
          return (
            <>
              <input
                type="text"
                name="data"
                value={formData.data || ''}
                onChange={handleInputChange}
                placeholder="Data to Encrypt for Crypto3"
              />
              <input
                type="text"
                name="encryptionKey"
                value={formData.encryptionKey || ''}
                onChange={handleInputChange}
                placeholder="Encryption Key for Crypto3"
              />
            </>
          );
        } else if (formType === 'Decode') {
          return (
            <>
              <input
                type="text"
                name="encodedData"
                value={formData.encodedData || ''}
                onChange={handleInputChange}
                placeholder="Encoded Data for Crypto3"
              />
              <input
                type="text"
                name="decryptionKey"
                value={formData.decryptionKey || ''}
                onChange={handleInputChange}
                placeholder="Decryption Key for Crypto3"
              />
            </>
          );
        }
        break;
      default:
        return null;
    }
  };

  return (
    <div>
      <h3>{formType} - {cryptosystemType}</h3>
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