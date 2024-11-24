// SectionB.js
import React, { useState, useEffect } from 'react';
import './SectionB.css';
import axios from 'axios';
function SectionB({ selectedItem, selectedSubItem, setSelectedSubItem, resetSelection }) {
  const [previousSubItem, setPreviousSubItem] = useState(null);
  const [cryptosystemType, setCryptosystemType] = useState(null);
  const [DSType, setDSType] = useState(null);
  const [algo, setAlgo] = useState(null);
  const [blogTitles, setBlogTitles] = useState([]);
  const [blogContent, setBlogContent] = useState(null);
  const [csystems_list, setCsystems_list] = useState([]);
  const [ds_list, setDS_list] = useState([]);
  const [algo_list, setAlgo_list] = useState([]);
  const [formData, setFormData] = useState({});
  const [apiResult, setApiResult] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  useEffect(() => {
    if (selectedItem && selectedItem === 'Blog') {
      // Fetch blog titles from the API
      axios.get('http://127.0.0.1:8000/myapp/blog/')
        .then(response => {
          const data = response.data;
          var list_of_blog = []
          for (var i = 0; i < data.length; i++) {
            list_of_blog.push({ "id": data[i]._id, "title": data[i].title, "content": data[i].content })
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
    if (selectedItem && selectedItem === 'DigitalSignature') {
      // Fetch blog titles from the API
      axios.get('http://127.0.0.1:8000/myapp/digitalsignature/')
        .then(response => {
          const data = response.data;
          var list_of_ds = [];
          for (var i = 0; i < data.length; i++) {
            list_of_ds.push({
              id: data[i]._id,
              title: data[i].title,
              fields: {
                create_key: data[i].fields.create_key,
                sign: data[i].fields.sign,
                verify: data[i].fields.verify
              }
            });
          }
          setDS_list(list_of_ds);
        })
        .catch(error => {
          console.error('There was an error fetching the digital signature scheme!', error);
        });
    }
  }, [selectedItem]);

  useEffect(() => {
    if (selectedItem && selectedItem === 'Algorithm') {
      // Fetch blog titles from the API
      axios.get('http://127.0.0.1:8000/myapp/algorithm/')
        .then(response => {
          const data = response.data;
          let algo_list = [];
          for (var i = 0; i < data.length; i++) {
            algo_list.push({
              id: data[i]._id,
              title: data[i].title,
              fields: {
                input: data[i].fields.input,
              }
            });
          }
          setAlgo_list(algo_list);
        })
        .catch(error => {
          console.error('There was an error fetching the algorithms!', error);
        });
    }
  }, [selectedItem]);

  useEffect(() => {
    setFormData({});
    setApiResult(null);
  }, [cryptosystemType]);
  useEffect(() => { setApiResult(null); }, [selectedSubItem]);

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });
  };

  const handleSubmit = async (e, apiUrl) => {
    e.preventDefault();
    setIsLoading(true); // Set loading state to true
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
    } finally {
      setIsLoading(false); // Reset loading state
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
            }}>Tạo khóa</li>
          )}
          <li onClick={() => {
            setPreviousSubItem(selectedSubItem);
            setSelectedSubItem('Encrypt');
          }}>Mã hóa</li>
          <li onClick={() => {
            setPreviousSubItem(selectedSubItem);
            setSelectedSubItem('Decrypt');
          }}>Giải mã</li>
        </ul>
      </div>
    );
  };

  const renderSubcontentDS = () => {
    if (!selectedSubItem) return null;
    return (
      <div>
        <h3>{selectedSubItem}</h3>
        <ul>
          <li onClick={() => {
            setPreviousSubItem(selectedSubItem);
            setSelectedSubItem('Create Key');
          }}>Tạo Khóa</li>
          <li onClick={() => {
            setPreviousSubItem(selectedSubItem);
            setSelectedSubItem('Sign');
          }}>Ký</li>
          <li onClick={() => {
            setPreviousSubItem(selectedSubItem);
            setSelectedSubItem('Verify');
          }}>Xác nhận chữ ký</li>
        </ul>
      </div>
    );
  }
  const renderSelectedContent = () => {
    if (!selectedItem) {
      return <div>
        {/* <h1>Mật mã và An toàn thông tin</h1>

        <h2>Giới thiệu về Mật mã và An toàn thông tin</h2>
        <p>
          <strong>Mật mã học</strong> (Cryptography) là lĩnh vực nghiên cứu các phương pháp bảo vệ thông tin và dữ liệu để đảm bảo tính bảo mật, toàn vẹn, và xác thực. Đây là một phần quan trọng trong lĩnh vực <strong>An toàn thông tin</strong> (Information Security), tập trung vào việc bảo vệ các thông tin khỏi truy cập trái phép và đảm bảo tính bảo mật của hệ thống.
        </p>
        <p>
          An toàn thông tin không chỉ bao gồm bảo mật về mặt kỹ thuật mà còn bao gồm cả các khía cạnh quản lý như chính sách bảo mật, quản lý truy cập, và giám sát hệ thống.
        </p>

        <h2>Vai trò của Mật mã và An toàn thông tin</h2>
        <ul>
          <li>
            <strong>Bảo vệ Dữ liệu</strong>: Mật mã đảm bảo rằng dữ liệu chỉ có thể được truy cập bởi những người có quyền, thông qua các kỹ thuật như mã hóa (encryption) và giải mã (decryption). Điều này giúp bảo vệ thông tin cá nhân, tài chính, và các thông tin nhạy cảm khác.
          </li>
          <li>
            <strong>Đảm bảo Tính Toàn Vẹn</strong>: Sử dụng các kỹ thuật như hàm băm (hashing), hệ thống có thể phát hiện nếu dữ liệu bị thay đổi hoặc bị giả mạo. Điều này đặc biệt quan trọng đối với các giao dịch tài chính và dữ liệu pháp lý.
          </li>
          <li>
            <strong>Xác thực</strong>: Các giao thức mật mã giúp xác định danh tính của người gửi và người nhận trong một giao dịch. Các công nghệ như chữ ký số (digital signature) đảm bảo rằng thông điệp không bị giả mạo.
          </li>
          <li>
            <strong>Bảo mật Giao tiếp</strong>: Mật mã cung cấp các phương pháp bảo vệ thông tin khi truyền qua các kênh không an toàn, chẳng hạn như Internet. Các giao thức như HTTPS, SSL/TLS được thiết kế để bảo vệ thông tin trong quá trình truyền tải.
          </li>
          <li>
            <strong>Phòng chống Tấn công</strong>: Bằng cách sử dụng mật mã và các biện pháp bảo mật khác, hệ thống có thể ngăn chặn các cuộc tấn công từ bên ngoài như nghe lén (eavesdropping), đánh cắp dữ liệu, và tấn công từ chối dịch vụ (DoS).
          </li>
        </ul>

        <h2>Ứng dụng thực tế của Mật mã và An toàn thông tin</h2>
        <ul>
          <li>
            <strong>Giao dịch Ngân hàng Trực tuyến</strong>: Các giao dịch ngân hàng qua mạng sử dụng các phương pháp mã hóa để đảm bảo thông tin tài chính của người dùng không bị lộ.
          </li>
          <li>
            <strong>Thương mại Điện tử</strong>: Trong các hệ thống thương mại điện tử, mật mã học được sử dụng để bảo vệ thông tin thanh toán và thông tin cá nhân của khách hàng.
          </li>
          <li>
            <strong>Email và Nhắn tin Bảo mật</strong>: Các ứng dụng email và nhắn tin sử dụng mã hóa đầu cuối (end-to-end encryption) để bảo vệ nội dung của các cuộc hội thoại.
          </li>
          <li>
            <strong>Blockchain và Tiền mã hóa</strong>: Mật mã học là nền tảng của các hệ thống blockchain và tiền mã hóa như Bitcoin và Ethereum, nơi thông tin về các giao dịch được bảo mật và không thể thay đổi.
          </li>
          <li>
            <strong>Xác thực Đa yếu tố (MFA)</strong>: Đây là một phương pháp bảo mật sử dụng nhiều lớp xác thực để bảo vệ tài khoản và hệ thống, chẳng hạn như mã OTP, ứng dụng xác thực, hoặc sinh trắc học.
          </li>
          <li>
            <strong>Quản lý Truy cập và Bảo mật Mạng</strong>: Các hệ thống bảo mật mạng như tường lửa (firewall), hệ thống phát hiện xâm nhập (IDS), và quản lý quyền truy cập đều sử dụng các nguyên tắc mật mã để bảo vệ thông tin.
          </li>
        </ul> */}

        Trang trống
      </div>;
    }
    if (selectedItem === 'Algorithm') {
      return (
        <div>
          <h2 className='title'>Algorithms</h2>
          <ul>
            {algo_list.map((algorithm, i) => (
              <li key={i} onClick={() => {
                setSelectedSubItem(algorithm.title)
                setPreviousSubItem(selectedSubItem)
                setAlgo(i);
              }}>
                {algorithm.title}
              </li>
            ))}
          </ul>
          <button onClick={() => { resetSelection(); setFormData(""); }}>Trang chủ</button>
        </div>
      );
    }
    if (selectedItem === 'Cryptosystem') {
      return (
        <div>
          <h2 className='title'>Hệ mật</h2>
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
          <button onClick={() => { resetSelection(); setFormData(""); }}>Trang chủ</button>
        </div>
      );
    }

    if (selectedItem === 'DigitalSignature') {
      return (
        <div>
          <h2 className='title'>Digital Signature</h2>
          <ul>
            {ds_list.map((dsscheme, i) => (
              <li key={i} onClick={() => {
                setSelectedSubItem(dsscheme.title);
                setDSType(i);
              }}>
                {dsscheme.title}
              </li>
            ))}
          </ul>
          {renderSubcontentDS()}
          <button onClick={() => { resetSelection(); setFormData(""); }}>Trang chủ</button>
        </div>
      );
    }

    if (selectedItem === 'Blog') {
      return (
        <div>
          <h2 className='title'>{selectedItem}</h2>
          <ul>
            {blogTitles.map((blog, index) => (
              <li key={index} onClick={() => {
                setSelectedSubItem(blog.title);
                setBlogContent(blog.content);
                setPreviousSubItem(selectedSubItem)
              }}>
                {blog.title}
              </li>
            ))}
          </ul>
          <button onClick={() => { resetSelection()}}>Trang chủ</button>
        </div>
      );
    }
  };
  const renderFormFieldsAlgo = () => {
    const formType = "input";
    const list_fields = algo_list[algo].fields[formType];
    if (!list_fields || list_fields.length === 0) {
      return null;
    }
    return list_fields.map((field, index) => (
      <input
        key={index}
        type={field.type}
        name={field.name}
        value={formData[field.name] || ''}
        onChange={handleInputChange}
        placeholder={field.placeholder}
        required
      />
    ));
  };
  const renderFormFields = () => {
    const formType = selectedSubItem.toLowerCase().replace(' ', '_');
    const list_fields = csystems_list[cryptosystemType].fields[formType];
    if (!list_fields || list_fields.length === 0) {
      return <p>No fields available for this form type.</p>;
    }
    return list_fields.map((field, index) => {
      if (field.type === 'textarea') {
        return (
          <textarea
            key={index}
            name={field.name}
            value={formData[field.name] || ''}
            onChange={handleInputChange}
            placeholder={field.placeholder}
            required
            {...(field.id && { id: field.id })} // Conditionally add the id attribute
          />
        );
      } else {
        return (
          <input
            key={index}
            type={field.type}
            name={field.name}
            value={formData[field.name] || ''}
            onChange={handleInputChange}
            placeholder={field.placeholder}
            required
            {...(field.id && { id: field.id })} // Conditionally add the id attribute
          />
        );
      }
    });
  };

  const renderFormFieldsDS = () => {
    const formType = selectedSubItem.toLowerCase().replace(' ', '_');
    const list_fields = ds_list[DSType].fields[formType];
    if (!list_fields || list_fields.length === 0) {
      return <p>No fields available for this form type.</p>;
    }

    return list_fields.map((field, index) => {
      if (field.type === 'textarea') {
        return (
          <textarea
            key={index}
            name={field.name}
            value={formData[field.name] || ''}
            onChange={handleInputChange}
            placeholder={field.placeholder}
            required
            {...(field.id && { id: field.id })} // Conditionally add the id attribute
          />
        );
      } else {
        return (
          <input
            key={index}
            type={field.type}
            name={field.name}
            value={formData[field.name] || ''}
            onChange={handleInputChange}
            placeholder={field.placeholder}
            required
            {...(field.id && { id: field.id })} // Conditionally add the id attribute
          />
        );
      }
    });
  };


  function renderObject(obj) {
    return Object.keys(obj).map((key) => (
      <div
        key={key}
        style={{
          marginBottom: '15px',
          marginLeft: '20px',
          padding: '10px',
          backgroundColor: '#f8f9fa', // Màu nền nhẹ để phân biệt các phần tử
          borderRadius: '5px',         // Bo góc cho đẹp hơn
          border: '1px solid #e0e0e0', // Viền nhẹ để phân cách
        }}
      >
        <strong style={{ color: '#333' }}>{key.replace(/_/g, ' ')}</strong>
        <div style={{ marginTop: '5px' }}>{renderValue(obj[key])}</div>
      </div>
    ));
  }

  function renderValue(value) {
    if (typeof value === 'object' && value !== null) {
      return (
        <div
          style={{
            marginLeft: '20px',
            paddingLeft: '10px',
            borderLeft: '3px solid #d0d0d0', // Viền trái để phân biệt cấp độ
            color: 'black', // Màu chữ đen cho các giá trị con
          }}
        >
          {renderObject(value)}
        </div>
      );
    } else {
      return (
        <div
          style={{
            whiteSpace: 'normal',
            wordBreak: 'break-word',
            overflowWrap: 'break-word',
            backgroundColor: '#ffffff', // Màu nền trắng cho các giá trị đơn
            padding: '5px',
            borderRadius: '3px',
            boxShadow: '0px 1px 3px rgba(0, 0, 0, 0.1)', // Tạo bóng nhẹ
          }}
        >
          {value.toString()}
        </div>
      );
    }
  }

  const renderContent = () => {
    if (!selectedItem) {
      return <div class="home">
        <h1>Mật mã và An toàn thông tin</h1>

        <h2>Giới thiệu về Mật mã và An toàn thông tin</h2>
        <p>
          <strong>Mật mã học</strong> (Cryptography) là lĩnh vực nghiên cứu các phương pháp bảo vệ thông tin và dữ liệu để đảm bảo tính bảo mật, toàn vẹn, và xác thực. Đây là một phần quan trọng trong lĩnh vực <strong>An toàn thông tin</strong> (Information Security), tập trung vào việc bảo vệ các thông tin khỏi truy cập trái phép và đảm bảo tính bảo mật của hệ thống.
        </p>
        <p>
          An toàn thông tin không chỉ bao gồm bảo mật về mặt kỹ thuật mà còn bao gồm cả các khía cạnh quản lý như chính sách bảo mật, quản lý truy cập, và giám sát hệ thống.
        </p>

        <h2>Vai trò của Mật mã và An toàn thông tin</h2>
        <ul>
          <li>
            <strong>Bảo vệ Dữ liệu</strong>: Mật mã đảm bảo rằng dữ liệu chỉ có thể được truy cập bởi những người có quyền, thông qua các kỹ thuật như mã hóa (encryption) và giải mã (decryption). Điều này giúp bảo vệ thông tin cá nhân, tài chính, và các thông tin nhạy cảm khác.
          </li>
          <li>
            <strong>Đảm bảo Tính Toàn Vẹn</strong>: Sử dụng các kỹ thuật như hàm băm (hashing), hệ thống có thể phát hiện nếu dữ liệu bị thay đổi hoặc bị giả mạo. Điều này đặc biệt quan trọng đối với các giao dịch tài chính và dữ liệu pháp lý.
          </li>
          <li>
            <strong>Xác thực</strong>: Các giao thức mật mã giúp xác định danh tính của người gửi và người nhận trong một giao dịch. Các công nghệ như chữ ký số (digital signature) đảm bảo rằng thông điệp không bị giả mạo.
          </li>
          <li>
            <strong>Bảo mật Giao tiếp</strong>: Mật mã cung cấp các phương pháp bảo vệ thông tin khi truyền qua các kênh không an toàn, chẳng hạn như Internet. Các giao thức như HTTPS, SSL/TLS được thiết kế để bảo vệ thông tin trong quá trình truyền tải.
          </li>
          <li>
            <strong>Phòng chống Tấn công</strong>: Bằng cách sử dụng mật mã và các biện pháp bảo mật khác, hệ thống có thể ngăn chặn các cuộc tấn công từ bên ngoài như nghe lén (eavesdropping), đánh cắp dữ liệu, và tấn công từ chối dịch vụ (DoS).
          </li>
        </ul>

        <h2>Ứng dụng thực tế của Mật mã và An toàn thông tin</h2>
        <ul>
          <li>
            <strong>Giao dịch Ngân hàng Trực tuyến</strong>: Các giao dịch ngân hàng qua mạng sử dụng các phương pháp mã hóa để đảm bảo thông tin tài chính của người dùng không bị lộ.
          </li>
          <li>
            <strong>Thương mại Điện tử</strong>: Trong các hệ thống thương mại điện tử, mật mã học được sử dụng để bảo vệ thông tin thanh toán và thông tin cá nhân của khách hàng.
          </li>
          <li>
            <strong>Email và Nhắn tin Bảo mật</strong>: Các ứng dụng email và nhắn tin sử dụng mã hóa đầu cuối (end-to-end encryption) để bảo vệ nội dung của các cuộc hội thoại.
          </li>
          <li>
            <strong>Blockchain và Tiền mã hóa</strong>: Mật mã học là nền tảng của các hệ thống blockchain và tiền mã hóa như Bitcoin và Ethereum, nơi thông tin về các giao dịch được bảo mật và không thể thay đổi.
          </li>
          <li>
            <strong>Xác thực Đa yếu tố (MFA)</strong>: Đây là một phương pháp bảo mật sử dụng nhiều lớp xác thực để bảo vệ tài khoản và hệ thống, chẳng hạn như mã OTP, ứng dụng xác thực, hoặc sinh trắc học.
          </li>
          <li>
            <strong>Quản lý Truy cập và Bảo mật Mạng</strong>: Các hệ thống bảo mật mạng như tường lửa (firewall), hệ thống phát hiện xâm nhập (IDS), và quản lý quyền truy cập đều sử dụng các nguyên tắc mật mã để bảo vệ thông tin.
          </li>
        </ul>
        <h4> Bắt đầu tìm hiểu cùng một số hệ mật và thuật toán cơ bản nhé.</h4>
      </div>;
    }

    switch (selectedItem) {
      case 'Algorithm':
        if (selectedSubItem) {
          let apiUrl = `http://127.0.0.1:8000/myapp/algorithm/${algo_list[algo].title?.toLowerCase().replace(/ /g, '_')}/`
          return (
            <div className="form-container">
              <h3 className='title'>{selectedSubItem}</h3>
              <form onSubmit={(e) => handleSubmit(e, apiUrl)}>
                {renderFormFieldsAlgo()}
                <button type="submit">Submit</button>
              </form>
              <button onClick={() => {setSelectedSubItem(previousSubItem); setFormData("");}}>Quay lại</button>
              {isLoading && <div className="loading-spinner"></div>}
                {apiResult && (
                  <div className="api-result">
                    <div style={{ padding: '10px', margin: '20px', borderRadius: '4px' }}>
                      {renderObject(apiResult)}
                    </div>
                  </div>
                )}
            </div>
          )
        }
        else { return renderSelectedContent(); }
      case 'Cryptosystem':
        switch (selectedSubItem) {
          case 'Create Key':
          case 'Encrypt':
          case 'Decrypt':
            let apiUrl = `http://127.0.0.1:8000/myapp/cryptosystem/${csystems_list[cryptosystemType].title?.toLowerCase().replace(/ /g, '_')}/${selectedSubItem.toLowerCase().replace(' ', '_')}/`
            return (
              <div className="form-container">
                <h3 className='title'>{selectedSubItem} - {csystems_list[cryptosystemType].title}</h3>
                <form onSubmit={(e) => handleSubmit(e, apiUrl)}>
                  {renderFormFields()}
                  <button type="submit">Submit</button>
                </form>
                <button onClick={() => {setSelectedSubItem(previousSubItem); setFormData("");}}>Quay lại</button>
                {isLoading && <div className="loading-spinner"></div>}
                {apiResult && (
                  <div className="api-result">
                    <div style={{ padding: '10px', margin: '20px', borderRadius: '4px' }}>
                      {renderObject(apiResult)}
                    </div>
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
            let ds_type = ds_list[DSType].title?.toLowerCase().replace(/ /g, '_')
            let apiUrl = `http://127.0.0.1:8000/myapp/digitalsignature/${ds_type}/${selectedSubItem.toLowerCase().replace(' ', '_')}/`
            return (
              <div className="form-container">
                <h3 className='title'>{selectedSubItem} - {ds_list[DSType].title}</h3>
                <form onSubmit={(e) => handleSubmit(e, apiUrl)}>
                  {renderFormFieldsDS()}
                  <button type="submit">Submit</button>
                </form>
                <button onClick={() => {setSelectedSubItem(previousSubItem); setFormData("");}}>Quay lại</button>
                {isLoading && <div className="loading-spinner"></div>}
                {apiResult && (
                  <div className="api-result">
                    <div style={{ padding: '10px', margin: '20px', borderRadius: '4px' }}>
                      {renderObject(apiResult)}
                    </div>
                  </div>
                )}
              </div>
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
              <button onClick={() => setSelectedSubItem(previousSubItem)}>Quay lại</button>
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