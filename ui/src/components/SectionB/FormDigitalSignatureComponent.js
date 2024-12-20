import React, { useState, useEffect } from 'react';

function FormComponentDS({ formType, DSType, apiUrl, onBack }) {
  const [formData, setFormData] = useState({});
  const [apiResult, setApiResult] = useState(null);

  useEffect(() => {
    setFormData({});
    setApiResult(null);
  }, [formType, DSType]);

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

  const renderFormFieldsDS = () => {
    if (!DSType) return null;

    switch (DSType) {
      case 'DSA':
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
        } else if (formType === 'Sign') {
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
        } else if (formType === 'Verify') {
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
      case 'Signature on RSA':
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
        } else if (formType === 'Sign') {
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
        } else if (formType === 'Verify') {
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
      case 'ECDSA':
        if (formType === 'Create Key') {
          return (
            <>
              <input
                type="number"
                name="bits"
                value={formData.bits || ''}
                onChange={handleInputChange}
                placeholder="Enter size of prime number"
              />
            </>
          );
        } else if (formType === 'Sign') {
          return (
            <>
              <input
                type="text"
                name="message"
                value={formData.message || ''}
                onChange={handleInputChange}
                placeholder="Enter message"
              /> <br/>
              <input
                type="number"
                name="a"
                value={formData.a || ''}
                onChange={handleInputChange}
                placeholder="Enter a"
              /> <br/>
              <input
                type="number"
                name="p"
                value={formData.p || ''}
                onChange={handleInputChange}
                placeholder="Enter p"
              /> <br/>
              <input
                type="number"
                name="Px"
                value={formData.Px || ''}
                onChange={handleInputChange}
                placeholder="Enter Px"
              />
              <input
                type="number"
                name="Py"
                value={formData.Py || ''}
                onChange={handleInputChange}
                placeholder="Enter Py"
              /> <br/>
              <input
                type="number"
                name="Bx"
                value={formData.Bx || ''}
                onChange={handleInputChange}
                placeholder="Data to Encrypt for Crypto3"
              /> 
              <input
                type="number"
                name="By"
                value={formData.By || ''}
                onChange={handleInputChange}
                placeholder="Enter By"
              /> <br/>
            </>
          );
        } else if (formType === 'Verify') {
          return (
            <>
              <input
                type="text"
                name="encrypted_message"
                value={formData.encrypted_message || ''}
                onChange={handleInputChange}
                placeholder="Encoded Message"
              />
              <input
                type="number"
                name="a"
                value={formData.a || ''}
                onChange={handleInputChange}
                placeholder="Enter a"
              /> <br/>
              <input
                type="number"
                name="p"
                value={formData.p || ''}
                onChange={handleInputChange}
                placeholder="Enter p"
              /> <br/>
              <input
                type="text"
                name="decryptionKey"
                value={formData.decryptionKey || ''}
                onChange={handleInputChange}
                placeholder="Enter s - private key"
              /> <br/>
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
      <h3>{formType} - {DSType}</h3>
      <form onSubmit={handleSubmit}>
        {renderFormFieldsDS()}
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

export default FormComponentDS;