#include <bits/stdc++.h>



std::vector<int> findMatch(std::map<std::string, int>* m, std::vector<std::string>* q){

    std::vector<int> res;

    std::string thisq;

    for(int i = 0 ; i < q->size(); i++){

        thisq = (*q)[i];

        if (m->find(thisq) == m->end()) {
            res.push_back(0);
        } else {
            res.push_back((*m)[thisq]);
        }

    }
    
    return res;
}



int main(){
    
    
    int list_count = 0;
    int query_count = 0;
    std::map<std::string, int> string_map;
    std::vector<std::string> queries;

    std::string tmp;

    std::getline(std::cin, tmp);

    list_count = std::stoi(tmp);

    for(int i = 0 ; i < list_count; i++){
        std::string item;
        std::getline(std::cin, item);

        if (string_map.find(item) == string_map.end()) {
            string_map[item] = 1;
        } else {
            string_map[item] += 1;
        }
    }

    std::getline(std::cin, tmp);

    query_count = std::stoi(tmp);

    for(int i = 0; i < query_count; i++){
        std::string item;
        std::getline(std::cin, item);
        queries.push_back(item);

    }

    std::vector<int> ans = findMatch(&string_map, &queries);

    for(int i = 0; i < ans.size(); i++){

        std::cout << ans[i] << std::endl;

    }


    return 0;
}