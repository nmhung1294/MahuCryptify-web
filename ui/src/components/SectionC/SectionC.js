// SectionC.js
import React from 'react';
import './SectionC.css';

function SectionC({ onSelectItem }) {
  const handleSelectItem = (item) => {
    onSelectItem(item);
  };

  return (
    <div className="section-c">
      {/* <div className="section-c1">Tìm kiếm</div> */}
      {/* <div className='section-c1'>
        <form className="login-form">
          <input type="text" placeholder="Username" required />
          <input type="password" placeholder="Password" required />
          <button id="login" type="submit">I have an account!</button>
        </form>
      </div> */}
      <div className="section-c2">
        <h3 className='can_click' onClick={() => handleSelectItem('Algorithm')}>Algorithm</h3>
        <h3 className='can_click' onClick={() => handleSelectItem('Cryptosystem')}>Cryptosystem</h3>
        <h3 className='can_click' onClick={() => handleSelectItem('DigitalSignature')}>Digital Signature</h3>
      </div>
      <div className="section-c3">
        {/* <h3 className='can_click' onClick = {() => handleSelectItem('Blog')}>Blog</h3> */}
        <h3>Blog</h3>
        <p className='introblog'>You can explore how algorithms work, how cryptographic systems operate, signature schemes, and more...
        <span className='can_click introblog' onClick = {() => handleSelectItem('Blog')}>Click here</span> </p>
      </div>
      <div className="section-c4">
        <h3>FAQs & Support</h3>
        <div className='support'>
          <a href="mailto:support@example.com">E-mail</a>
        </div>
      </div>
    </div>
  );
}

export default SectionC;