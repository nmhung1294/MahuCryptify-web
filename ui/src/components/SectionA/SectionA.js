// SectionA.js
import React from 'react';
import './SectionA.css';
import facebookImage from './Facebook.png';
function SectionA() {
  return (
    <div className="section-a">
      <div className="section-a1"></div>
      <div className="section-a2">
        <h3>Introduction</h3>
        <div>
          <p id='intro'> Here is a collection of algorithms, cryptographic systems, and articles sharing knowledge related to cryptography and information security.</p>
        </div>
      </div>
      <div className="section-a3">
        <h3>Social Media</h3>
        <div className='smedia'>
            <a id='facebook' href='https://www.facebook.com/profile.php?id=100032542596283'><img className='social-media-image' src={facebookImage} alt='Facebook'/></a>
        </div>
      </div>
    </div>
  );
}

export default SectionA;