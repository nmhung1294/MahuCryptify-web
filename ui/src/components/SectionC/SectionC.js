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
      <div className="section-c2">
        <h3 className='can_click' onClick={() => handleSelectItem('Algorithm')}>Algorithm</h3>
        <h3 className='can_click' onClick={() => handleSelectItem('Cryptosystem')}>Cryptosystem</h3>
        <h3 className='can_click' onClick={() => handleSelectItem('DigitalSignature')}>Digital Signature</h3>
      </div>
      <div className="section-c3">
        <h3 className='can_click' onClick = {() => handleSelectItem('Blog')}>Blog</h3>
        <p className='introblog'> Bạn có thể tìm đọc cách mà các thuật toán, cách mà các hệ mật hoạt động, sơ đồ chữ ký...</p>
        <h4 className='can_click introblog' onClick = {() => handleSelectItem('Blog')}>Click here</h4>
      </div>
      <div className="section-c3">
        <h3>Support</h3>
        <a href="mailto:support@example.com">Gửi mail</a>
      </div>
    </div>
  );
}

export default SectionC;