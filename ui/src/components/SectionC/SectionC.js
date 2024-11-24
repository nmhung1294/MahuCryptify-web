// SectionC.js
import React from 'react';
import './SectionC.css';

function SectionC({ onSelectItem }) {
  const handleSelectItem = (item) => {
    onSelectItem(item);
  };

  return (
    <div className="section-c">
      {/*Tạm thời khóa đăng nhập */}
      {/* <div className="section-c1">Tìm kiếm</div> */}
      {/* <div className='section-c1'>
        <form className="login-form">
          <input type="text" placeholder="Username" required />
          <input type="password" placeholder="Password" required />
          <button id="login" type="submit">I have an account!</button>
        </form>
      </div> */}
      <div className="section-c2">
        <h3 className='can_click' onClick={() => handleSelectItem('Algorithm')}>Thuật toán</h3>
        <h3 className='can_click' onClick={() => handleSelectItem('Cryptosystem')}>Các hệ mật</h3>
        <h3 className='can_click' onClick={() => handleSelectItem('DigitalSignature')}>Chữ ký số</h3>
      </div>
      <div className="section-c3">
        <h3>Lý thuyết</h3>  {/*Ban đầu đặt là blog, gần cuối sửa */}
        <p className='introblog'>Bạn có thể khám phá cách các thuật toán hoạt động, cách các hệ thống mật mã vận hành, các sơ đồ chữ ký, và nhiều thứ khác...
        <span className='can_click introblog' onClick = {() => handleSelectItem('Blog')}>Click vào đây</span> </p>
      </div>
      <div className="section-c4">
        <h3>Hỗ trợ</h3>
        <div className='support'>
          <a href="mailto:support@example.com">E-mail</a>
        </div>
      </div>
    </div>
  );
}

export default SectionC;