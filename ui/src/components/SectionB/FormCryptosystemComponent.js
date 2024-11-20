import React, { useState, useEffect } from 'react';
import './cryptosystemcss.css'
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
                className='inp_message'
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
                className='inp_message'
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
                type="number"
                name="bits"
                value={formData.bits || ''}
                onChange={handleInputChange}
                placeholder="Enter size of prime number"
              />
            </>
          );
        } else if (formType === 'Encrypt') {
          return (
            <>
              <input
                type="text"
                name="message"
                className='inp_message'
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
        } else if (formType === 'Decrypt') {
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
    <div className="form-container">
    <h3 className='title'>{formType} - {cryptosystemType}</h3>
    <form onSubmit={handleSubmit}>
      {renderFormFields()}
      <button type="submit">Submit</button>
    </form>
    <button onClick={onBack}>Back</button>
    {apiResult && (
      <div className="api-result">
        <h4>API Result:</h4>
        <textarea
           value={JSON.stringify(apiResult, (key, value) => {
            if (typeof value === 'number') {
              return value.toString();
            }
            return value;
          }, 2)}
          readOnly 
          rows={10}
          style={{ width: '90%', padding: '10px',margin: '20px', borderRadius: '4px', border: '1px solid #ccc' }} // Thêm kiểu
        />
      </div>
    )}
  </div>
  );
}

export default FormComponent;