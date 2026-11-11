-- AI-Security-Audit-Skills test fixture | Vijaya Kumar L (Rise With VJ) | github.com/risewithvj | MIT
CREATE TABLE employees (id SERIAL PRIMARY KEY, org_id INT, name TEXT, email TEXT, phone TEXT, department TEXT, date_of_birth DATE, aadhaar_number VARCHAR(12), pan VARCHAR(10));
CREATE TABLE payslips (id SERIAL PRIMARY KEY, employee_id INT, month TEXT, net_pay NUMERIC, bank_account_no TEXT, ifsc TEXT, pan VARCHAR(10), pdf BYTEA);
