// SectionB.js
import React, { useState, useEffect } from 'react';
import './SectionB.css';
import FormComponent from './FormCryptosystemComponent';
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
  useEffect(() => {
    if (selectedItem && selectedItem === 'Blog') {
      // Fetch blog titles from the API
      axios.get('http://127.0.0.1:8000/myapp/blog/')
        .then(response => {
          const data = response.data;
          console.log(response);
          console.log(data);
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
            {list_of_cryptosystems.map((cryptosystemType, i) => (
              <li key={i} onClick={() => {
                setSelectedSubItem(cryptosystemType);
                setCryptosystemType(cryptosystemType);
              }}>
                {cryptosystemType}
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
            return (
              <FormComponent
                formType={selectedSubItem}
                cryptosystemType={cryptosystemType}
                apiUrl={`http://127.0.0.1:8000/myapp/cryptosystem/${cryptosystemType?.toLowerCase().replace(' ', '_')}/${selectedSubItem.toLowerCase().replace(' ', '_')}/`}
                onBack={() => setSelectedSubItem(previousSubItem)}
              />
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
                <p>{blogContent}</p>
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