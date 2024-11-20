// SectionB.js
import React, { useState, useEffect } from 'react';
import './SectionB.css';
import FormComponentDS from './FormDigitalSignatureComponent';
import FormComponentAlgo from './FormAlgoComponent';
import axios from 'axios';
function SectionB({ selectedItem, selectedSubItem, setSelectedSubItem, resetSelection }) {
  const [previousSubItem, setPreviousSubItem] = useState(null);
  const [cryptosystemType, setCryptosystemType] = useState(null);
  const [DSType, setDSType] = useState(null);
  const [algo, setAlgo] = useState(null);
  const [blogTitles, setBlogTitles] = useState([]);
  const [blogContent, setBlogContent] = useState(null);
  const [csystems_list, setCsystems_list] = useState([]);
  const [formData, setFormData] = useState({});
  const [apiResult, setApiResult] = useState(null);
  
  useEffect(() => {
    if (selectedItem && selectedItem === 'Blog') {
      // Fetch blog titles from the API
      axios.get('http://127.0.0.1:8000/myapp/blog/')
        .then(response => {
          const data = response.data;
          var list_of_blog = []
          for (var i = 0; i < data.length; i++) {
            list_of_blog.push({"id" : data[i]._id, "title" : data[i].title, "content" : data[i].content})
          }
          setBlogTitles(list_of_blog);
        })
        .catch(error => {
          console.error('There was an error fetching the blog titles!', error);
        });
    }
  }, [selectedItem]);
  
  useEffect(() => {
    if (selectedItem && selectedItem === 'Cryptosystem') {
      // Fetch blog titles from the API
      axios.get('http://127.0.0.1:8000/myapp/cryptosystems/')
        .then(response => {
          const data = response.data;
          var list_of_csystems = [];
          for (var i = 0; i < data.length; i++) {
            list_of_csystems.push({
              id: data[i]._id, 
              title: data[i].title,
              fields: { 
                create_key: data[i].fields.create_key, 
                encrypt: data[i].fields.encrypt,
                decrypt: data[i].fields.decrypt
              },
              encrypt: data[i].encrypt, 
              decrypt: data[i].decrypt 
            });
          }
          setCsystems_list(list_of_csystems);
        })
        .catch(error => {
          console.error('There was an error fetching the cryptosystems!', error);
        });
    }
  }, [selectedItem]);

  useEffect(() => {
    setFormData({});
    setApiResult(null);
  }, [cryptosystemType]);
  useEffect(() => {setApiResult(null);}, [selectedSubItem]);

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });
  };

  const handleSubmit = async (e, apiUrl) => {
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

  const renderSubItemContent = () => {
    if (!selectedSubItem) return null;
    const excludedSubItems = ['Shift Cipher', 'Vigenère Cipher', 'Hill Cipher', 'Affine Cipher'];
    return (
      <div>
        <h3>{selectedSubItem}</h3>
        <ul>
          {!excludedSubItems.includes(selectedSubItem) && (
            <li onClick={() => {
              setPreviousSubItem(selectedSubItem);
              setSelectedSubItem('Create Key');
            }}>Create Key</li>
          )}
          <li onClick={() => {
            setPreviousSubItem(selectedSubItem);
            setSelectedSubItem('Encrypt');
          }}>Encrypt</li>
          <li onClick={() => {
            setPreviousSubItem(selectedSubItem);
            setSelectedSubItem('Decrypt');
          }}>Decrypt</li>
        </ul>
      </div>
    );
  };

  const renderSubcontentDS= () => {
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
            setSelectedSubItem('Sign');
          }}>Sign</li>
          <li onClick={() => {
            setPreviousSubItem(selectedSubItem);
            setSelectedSubItem('Verify');
          }}>Verify Signature</li>
        </ul>
      </div>
    );
  }
  const renderSelectedContent = () => {
    var list_of_algorithms = ['AKS', 'Extend EuClide', 'Modular Exponentiation']
    const list_of_cryptosystems = ['RSA', 'ElGamal', 'Elliptic Curve']
    const list_of_digitalsignatures = ['DSA', 'Signature on RSA', 'Signature on ElGammal', 'ECDSA', 'Schnorr']
    if (!selectedItem) {
      return <div>Trang trống màu xanh</div>;
    }

    if (selectedItem === 'Algorithm') {
      return (
        <div>
          <h2 className='title'>Algorithms</h2>
          <ul>
            {list_of_algorithms.map((algorithm, i) => (
              <li key={i} onClick={() => {
                setSelectedSubItem(algorithm)
                setAlgo(algorithm);
              }}>
                {algorithm}
              </li>
            ))}
          </ul>
          <button onClick={resetSelection}>Back to Main</button>
        </div>
      );
    }
    if (selectedItem === 'Cryptosystem') {
      return (
        <div>
          <h2 className='title'>Cryptography Systems</h2>
          <ul>
            {csystems_list.map((cryptosystemType, i) => (
              <li key={i} onClick={() => {
                setSelectedSubItem(cryptosystemType.title);
                setCryptosystemType(i);
              }}>
                {cryptosystemType.title}
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
          <h2 className='title'>Digital Signature</h2>
          <ul>
            {list_of_digitalsignatures.map((dsscheme, i) => (
              <li key={i} onClick={() => {
              setSelectedSubItem(dsscheme);
              setDSType(dsscheme);
              }}>
                {dsscheme}
              </li>
            ))}
          </ul>
          {renderSubcontentDS()}
        </div>
      );
    }

    if (selectedItem ==='Blog') {
      return (
        <div>
          <h2 className='title'>{selectedItem}</h2>
          <ul>
            {blogTitles.map((blog, index) => (
              <li key={index} onClick = {() => {setSelectedSubItem(blog.title); setBlogContent(blog.content)}}>{blog.title}</li>
            ))}
          </ul>
        </div>
      );
    }
  };

  const renderFormFields = () => {
    const formType = selectedSubItem.toLowerCase().replace(' ', '_');
    const list_fields = csystems_list[cryptosystemType].fields[formType];
    if (!list_fields || list_fields.length === 0) {
      return <p>No fields available for this form type.</p>;
    }
  
    return list_fields.map((field, index) => (
      <input
        key={index}
        type={field.type}
        name={field.name}
        value={formData[field.name] || ''}
        onChange={handleInputChange}
        placeholder={field.placeholder}
      />
    ));
  };

  const renderContent = () => {
    if (!selectedItem) {
      return <div>Trang trống màu xanh</div>;
    }

    switch (selectedItem) {
      case 'Algorithm':
        if (selectedSubItem) {
          return (
            <FormComponentAlgo
              algo = {selectedSubItem}
              apiUrl={`http://127.0.0.1:8000/myapp/algo/${algo?.toLowerCase().replace(' ', '_')}/`}
              onBack={() => setSelectedSubItem(previousSubItem)}
            />
          )
        }
        else {return renderSelectedContent();}
      case 'Cryptosystem':
        switch (selectedSubItem) {
          case 'Create Key': 
          case 'Encrypt':
          case 'Decrypt':
            var form_type = selectedSubItem.toLowerCase().replace(' ', '_')
            var apiUrl=`http://127.0.0.1:8000/myapp/cryptosystem/${csystems_list[cryptosystemType].title?.toLowerCase().replace(' ', '_')}/${selectedSubItem.toLowerCase().replace(' ', '_')}/`
            return (
              <div className="form-container">
                <h3 className='title'>{selectedSubItem} - {csystems_list[cryptosystemType].title}</h3>
                <form onSubmit={(e) => handleSubmit(e, apiUrl)}>
                  {renderFormFields()}
                  <button type="submit">Submit</button>
                </form>
                <button onClick={() => setSelectedSubItem(previousSubItem)}>Back</button>
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
          default:
            return renderSelectedContent();
        };
        case 'DigitalSignature':
          switch (selectedSubItem) {
            case 'Create Key':
            case 'Sign':
            case 'Verify':
              return (
                <FormComponentDS
                  formType={selectedSubItem}
                  DSType={DSType}
                  apiUrl={`http://127.0.0.1:8000/myapp/digitalsignature/${DSType?.toLowerCase().replace(' ', '_')}/${selectedSubItem.toLowerCase().replace(' ', '_')}/`}
                  onBack={() => setSelectedSubItem(previousSubItem)}
                />
              );
            default:
              return renderSelectedContent();
          };
        case 'Blog':
          if (selectedSubItem) {
            return (
              <div>
                <h2>{selectedSubItem}</h2>
                <div dangerouslySetInnerHTML={{ __html: blogContent }} />
                <button onClick={resetSelection}>Back to Main</button>
              </div>
            )
          }
          else return renderSelectedContent();
      default:
        return null;
      };
};
  return (
    <div className="section-b">
      {renderContent()}
    </div>
  );
}

export default SectionB;