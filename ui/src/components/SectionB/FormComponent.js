import React, { useState, useEffect } from 'react';
import Cookies from 'js-cookie';
function FormComponent({ formType, cryptosystemType, apiUrl, onBack }) {
  const [formData, setFormData] = useState({});
  const [apiResult, setApiResult] = useState(null);

  useEffect(() => {
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
      // Lấy kết quả từ API Django
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
                type="number"
                name="n"
                value={formData.n || ''}
                onChange={handleInputChange}
                placeholder="Enter n for RSA"
              /> <br/>
              <input
                type="number"
                name="e"
                value={formData.e || ''}
                onChange={handleInputChange}
                placeholder="Enter e for RSA"
              /> <br/>
              <input
                type="text"
                name="message"
                value={formData.message || ''}
                onChange={handleInputChange}
                placeholder="Message to Encrypt using RSA"
              />
            </>
          );
        } else if (formType === 'Decrypt') {
          return (
            <>
              <input
                type="text"
                name="encrypted_message"
                value={formData.encrypted_message || ''}
                onChange={handleInputChange}
                placeholder="Encoded Data for Crypto1"
              />
              <input
                type="text"
                name="p"
                value={formData.p || ''}
                onChange={handleInputChange}
                placeholder="Enter p for RSA"
              /> <br/>
              <input
                type="text"
                name="q"
                value={formData.q || ''}
                onChange={handleInputChange}
                placeholder="Enter q for RSA"
              /> <br/>
              <input
                type="text"
                name="d"
                value={formData.d || ''}
                onChange={handleInputChange}
                placeholder="Enter d for RSA"
              /> <br/>
            </>
          );
        }
        break;
      case 'ElGamal':
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
                name="message"
                value={formData.message || ''}
                onChange={handleInputChange}
                placeholder="Data to Encrypt for Elgamal"
              /> <br/>
              <input
                type="number"
                name="p"
                value={formData.p|| ''}
                onChange={handleInputChange}
                placeholder="Encryption Key p"
              /> <br/>
              <input
                type="number"
                name="alpha"
                value={formData.alpha|| ''}
                onChange={handleInputChange}
                placeholder="Encryption Key alpha"
              /> <br/>
              <input
                type="number"
                name="beta"
                value={formData.beta|| ''}
                onChange={handleInputChange}
                placeholder="Encryption Key beta"
              /> <br/>
            </>
          );
        } else if (formType === 'Decrypt') {
          return (
            <>
              <input
                type="text"
                name="encrypted_message"
                value={formData.encrypted_message || ''}
                onChange={handleInputChange}
                placeholder="Data to Encrypt for Elgamal"
              /> <br/>
              <input
                type="number"
                name="p"
                value={formData.p|| ''}
                onChange={handleInputChange}
                placeholder="Decryption Key p"
              /> <br/>
              <input
                type="number"
                name="a"
                value={formData.a|| ''}
                onChange={handleInputChange}
                placeholder="Decryption Key a"
              /> <br/>
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