// SectionA.js
import React from 'react';
import './SectionA.css';
import facebookImage from './Facebook.png';
function SectionA() {
  return (
    <div className="section-a">
      <div className="section-a1"></div>
      <div className="section-a2">
        <h3>Giới thiệu</h3>
        <div>
          <p id='intro'> Đây là nơi tổng hợp các thuật toán, hệ thống mật mã, và các bài viết chia sẻ kiến thức liên quan đến mật mã và an toàn thông tin.</p>
        </div>
      </div>
      <div className="section-a3">
        <h3>Cộng đồng</h3>
        <div className='smedia'>
            <a id='facebook' href='https://www.facebook.com/groups/929813565139988'><img className='social-media-image' src={facebookImage} alt='Facebook'/></a>
        </div>
      </div>
    </div>
  );
}

export default SectionA;