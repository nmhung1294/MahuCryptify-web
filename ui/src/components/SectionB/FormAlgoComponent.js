import React, { useState, useEffect } from 'react';

function FormComponentAlgo({ algo, apiUrl, onBack }) {
  const [formData, setFormData] = useState({});
  const [apiResult, setApiResult] = useState(null);

  useEffect(() => {
    setFormData({});
    setApiResult(null);
  }, [algo]);

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
    if (!algo) return null;

    switch (algo) {
      case 'AKS':
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
      case 'Extend EuClide':
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
      case 'Modular Exponentiation':
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
      default:
        return null;
    }
  };

  return (
    <div>
      <h3>{algo}</h3>
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

export default FormComponentAlgo;