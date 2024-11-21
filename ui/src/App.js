// App.js
import React, { useState } from 'react';
import './App.css';
import SectionA from './components/SectionA/SectionA';
import SectionB from './components/SectionB/SectionB';
import SectionC from './components/SectionC/SectionC';

function App() {
  const [selectedItem, setSelectedItem] = useState(null);
  const [selectedSubItem, setSelectedSubItem] = useState(null);

  const handleSelectItem = (item) => {
    setSelectedItem(item);
    setSelectedSubItem(null);
  };

  const resetSelection = () => {
    setSelectedItem(null);
    setSelectedSubItem(null);
  };

  return (
    <div className="container">
      <SectionA />
      <SectionB
        selectedItem={selectedItem}
        selectedSubItem={selectedSubItem}
        setSelectedSubItem={setSelectedSubItem}
        resetSelection={resetSelection}
      />
      <SectionC onSelectItem={handleSelectItem} />
    </div>
  );
}

export default App;