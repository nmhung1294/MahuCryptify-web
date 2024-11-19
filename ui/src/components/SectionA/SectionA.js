// SectionA.js
import React from 'react';
import './SectionA.css';

function SectionA() {
  return (
    <div className="section-a">
      <div className="section-a1">Logo</div>
      <div className="section-a2">
        <h3>Giới thiệu</h3>
        <div>
          <p id='intro'> Đây là nơi tổng hợp các thuật toán, hệ mật mã, các bài viết chia sẻ liên quan đến mật mã và an toàn thông tin</p>
        </div>
      </div>
      <div className="section-a3">
        <h3>Social Media</h3>
        <div className='smedia'>
            <a id='facebook' href='https://www.facebook.com/profile.php?id=100032542596283'>Facebook</a>
        </div>
      </div>
    </div>
  );
}

export default SectionA;