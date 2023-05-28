#include "user.h"
#include "database.h"
#include "../config/config.h"

#include <Poco/Data/MySQL/Connector.h>
#include <Poco/Data/MySQL/MySQLException.h>
#include <Poco/Data/SessionFactory.h>
#include <Poco/Data/RecordSet.h>
#include <Poco/JSON/Parser.h>
#include <Poco/Dynamic/Var.h>

#include <sstream>
#include <exception>

#define TABLE_NAME "_user"

using namespace Poco::Data::Keywords;
using Poco::Data::Session;
using Poco::Data::Statement;

namespace database {
    long User::auth(std::string &login, std::string &password) {
        try {
            std::cout << "Trying to auth " << login << "::" << password << std::endl;
            Poco::Data::Session session = database::Database::get().create_session();
            std::cout << "Session created" << std::endl;
            Poco::Data::Statement select(session);
            long id;
            select << "SELECT id FROM " << TABLE_NAME << " where login=? and password=? and deleted = false",
                into(id),
                use(login),
                use(password),
                range(0, 1);

            select.execute();
            Poco::Data::RecordSet rs(select);
            if (rs.moveFirst()) return id;
        } catch (Poco::Data::DataException &e) {
            std::cout << "Exception: " << e.what() << " :: " << e.message() << std::endl;
            return -1;
        }
        return 0;
    }

    bool User::have_role(long user_id, std::string role_name) {
        try {
            Poco::Data::Session session = database::Database::get().create_session();
            Poco::Data::Statement select(session);
            
            bool result = false;

            select << "select true from _users_roles ur "
                << "inner join _roles r on r.id = ur.role_id "
                << "where ur.user_id = ? and r.name = ?",
                into(result),
                use(user_id),
                use(role_name),
                range(0, 1);
        
            select.execute();
            Poco::Data::RecordSet rs(select);
            if (rs.moveFirst())
                return result;

            return false;
        } catch (Poco::Data::MySQL::ConnectionException &e) {
            std::cout << "connection:" << e.what() << " :: " << e.message() << std::endl;
            throw;
        } catch (Poco::Data::MySQL::StatementException &e) {
            std::cout << "statement:" << e.what() << " :: " << e.message() << std::endl;
            throw;
        }
    }

    User User::get_by_id(long id) {
        try {
            Poco::Data::Session session = database::Database::get().create_session();
            Poco::Data::Statement select(session);
            User user;

            select << "select id, login, email, name, deleted from "  << TABLE_NAME << " where id = ?",
                into(user._id),
                into(user._login),
                into(user._email),
                into(user._name),
                into(user._deleted),
                use(id),
                range(0, 1);
        
            select.execute();
            Poco::Data::RecordSet rs(select);
            if (rs.moveFirst())
                return user;

            return User::empty();
        } catch (Poco::Data::MySQL::ConnectionException &e) {
            std::cout << "connection:" << e.what() << std::endl;
            throw;
        } catch (Poco::Data::MySQL::StatementException &e) {
            std::cout << "statement:" << e.what() << std::endl;
            throw;
        }
    }

    void User::save_to_db() {
        if (_id > 0) {
            update_entity();
        } else {
            insert_entity();
        }
    }

    void User::insert_entity() {
        Poco::Data::Session session = database::Database::get().create_session();
        session.begin();
        try {
            Poco::Data::Statement statement(session);

            statement << "INSERT INTO " << TABLE_NAME << " (name, email, login, password) VALUES(?, ?, ?, ?)",
                use(_name),
                use(_email),
                use(_login),
                use(_password);

            statement.execute();

            Poco::Data::Statement select(session);
            select << "SELECT LAST_INSERT_ID()",
                into(_id),
                range(0, 1);

            if (!select.done()){
                select.execute();
            }
            session.commit();
            
            std::cout << "New entity id:" << _id << std::endl;
        } catch (Poco::Data::MySQL::ConnectionException &e) {
            session.rollback();
            std::cout << "connection:" << e.what() << " :: " << e.message() << std::endl;
            throw;
        } catch (Poco::Data::MySQL::StatementException &e) {
            session.rollback();
            std::cout << "statement:" << e.what() << " :: " << e.message() << std::endl;
            throw;
        }
    }

    void User::update_entity() {
        Poco::Data::Session session = database::Database::get().create_session();
        session.begin();
        try {
            Poco::Data::Statement statement(session);

            statement << "update " << TABLE_NAME << " set name = ?, email = ? , login = ? , password = ?, deleted = ? where id = ?",
                use(_name),
                use(_email),
                use(_login),
                use(_password),
                use(_deleted),
                use(_id);

            statement.execute();

            Poco::Data::Statement select(session);
            int updated = -1;
            select << "SELECT ROW_COUNT();",
                into(updated),
                range(0, 1);

            if (!select.done()){
                select.execute();
            }
            session.commit();

            std::cout << "Updated:" << updated << std::endl;
        } catch (Poco::Data::MySQL::ConnectionException &e) {
            session.rollback();
            std::cout << "connection:" << e.what() << " :: " << e.message() << std::endl;
            throw;
        } catch (Poco::Data::MySQL::StatementException &e) {
            session.rollback();
            std::cout << "statement:" << e.what() << " :: " << e.message() << std::endl;
            throw;
        }
    }

    std::vector<User> User::search(User likeUser) {
        try {
            Poco::Data::Session session = database::Database::get().create_session();
            Poco::Data::Statement select(session);
            
            std::vector<User> result;
            User user;

            std::vector<std::string> conditions;

            if (likeUser.get_name().length() > 0) {
                std::replace(likeUser.name().begin(), likeUser.name().end(), ' ', '%');
                conditions.push_back("lower(name) like '%" + likeUser.get_name() + "%'");
            }

            if (likeUser.get_login().length() > 0) {
                std::replace(likeUser.login().begin(), likeUser.login().end(), ' ', '%');
                conditions.push_back("lower(login) like '%" + likeUser.get_login() + "%'");
            }

            if (likeUser.get_email().length() > 0) {
                conditions.push_back("lower(email) like '%" + likeUser.get_email() + "%'");
            }

            select << "select id, login, email, name, deleted from "  << TABLE_NAME << " where deleted = false",
                into(user._id),
                into(user._login),
                into(user._email),
                into(user._name),
                into(user._deleted),
                range(0, 1);

            if (conditions.size() > 0) {
                std::string cond_str;
                for (std::string cond: conditions) {
                    cond_str += " and " + cond;
                }
                std::cout << "Search condition: " << cond_str << std::endl;
                
                select << cond_str;
            }
        
            while (!select.done()){
                if (select.execute())
                    result.push_back(user);
            }            
            return result;
        } catch (Poco::Data::MySQL::ConnectionException &e) {
            std::cout << "connection:" << e.what() << " :: " << e.message() << std::endl;
            throw;
        } catch (Poco::Data::MySQL::StatementException &e) {
            std::cout << "statement:" << e.what() << " :: " << e.message() << std::endl;
            throw;
        }
    }

    Poco::JSON::Object::Ptr User::toJSON() const {
        Poco::JSON::Object::Ptr root = new Poco::JSON::Object();

        root->set("id", _id);
        root->set("name", _name);
        root->set("email", _email);
        root->set("login", _login);
        root->set("deleted", _deleted);

        return root;
    }

    template<typename T>
    T getOrDefault(Poco::JSON::Object::Ptr object, std::string field, T defaultValue) {
        if (object->has(field)) {
            return object->getValue<T>(field);
        }
        return defaultValue;
    }

    User User::fromJson(const std::string &str) {
        User user;
        Poco::JSON::Parser parser;
        Poco::Dynamic::Var result = parser.parse(str);
        Poco::JSON::Object::Ptr object = result.extract<Poco::JSON::Object::Ptr>();
        
        user.id() = getOrDefault<long>(object, "id", 0);
        user.name() = getOrDefault<std::string>(object, "name", "");
        user.email() = getOrDefault<std::string>(object, "email", "");
        user.login() = getOrDefault<std::string>(object, "login", "");
        user.password() = getOrDefault<std::string>(object, "password", "");
        user.deleted() = getOrDefault<bool>(object, "deleted", false);

        return user;
    }

    const std::string &User::get_login() const {
        return _login;
    }

    const std::string &User::get_password() const {
        return _password;
    }

    std::string &User::login() {
        return _login;
    }

    std::string &User::password() {
        return _password;
    }

    long User::get_id() const {
        return _id;
    }

    const std::string &User::get_name() const {
        return _name;
    }

    const std::string &User::get_email() const {
        return _email;
    }

    long &User::id() {
        return _id;
    }

    std::string &User::name() {
        return _name;
    }

    std::string &User::email() {
        return _email;
    }

    bool User::is_deleted() const {
        return _deleted;
    }

    bool &User::deleted() {
        return _deleted;
    }
}