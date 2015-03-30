
    // Temp Charts
    var randomScalingFactor = function () {
        return Math.round(Math.random() * 100);
    };

    var pieData = [
            {
                value: 300,
                color: "#3FB618;",
                highlight: "#65c446",
                label: "Alive"
            },
            {
                value: 50,
                color: "#FF7518",
                highlight: "#ff9046",
                label: "Unresponsive"
            }

    ];
    var doughnutData = [
            {
                value: 300,
                color: "#F7464A",
                highlight: "#FF5A5E",
                label: "Monday"
            },
            {
                value: 50,
                color: "#46BFBD",
                highlight: "#5AD3D1",
                label: "Tuesday"
            },
            {
                value: 100,
                color: "#FDB45C",
                highlight: "#FFC870",
                label: "Wednesday"
            },
            {
                value: 40,
                color: "#949FB1",
                highlight: "#A8B3C5",
                label: "Thursday"
            },
            {
                value: 120,
                color: "#4D5360",
                highlight: "#616774",
                label: "Friday"
            },
            {
                value: 40,
                color: "#006600",
                highlight: "#007f00",
                label: "Saturday"
            },
            {
                value: 40,
                color: "#8c198c",
                highlight: "#993299",
                label: "Sunday"
            }
    ];
    window.onload = function () {
        var ctz = document.getElementById("dailyDoughnutChart").getContext("2d");
        var cty = document.getElementById("randomPieChart").getContext("2d");

        window.myPie = new Chart(cty).Pie(pieData);
        window.myDoughnut = new Chart(ctz).Doughnut(doughnutData, {
            responsive: true
        });
    };

    // Tabs
    $('#wtTabs a').click(function (e) {
        e.preventDefault();
        $(this).tab('show');
    });

    // WebGrid additional styling and functionality
    $(function () {
        
        // Grid
        gridLayout();

        // Tooltips
        $('.a-c-tt').tooltip();
        $('.a-a-tt').tooltip();
        $('.a-u-tt').tooltip();




        $("#subT tfoot tr td a").click(function () {
             
        });
    });
 
    function gridLayout() {
        // Replace the Status text with visual aids
        $(".statusCheck:contains('1')").html("<span class='oi agent-active' data-glyph='media-record'></span><span class='agent-active'>Active</span>");
        $(".statusCheck:contains('0')").html("<span class='oi agent-unresp' data-glyph='media-record'></span><span class='agent-unresp'>Not Responding</span>");


        event.preventDefault();

        // Pagination fix for styling
        var currentPage = $("td").contents().filter(function () {
            if (this.nodeType === 3) {
                return $.trim(this.textContent) !== "";
            }
            return false;
        }).get(0);
        $(currentPage).wrap('<a class="current" />');
        $(".current").text($.trim($(".current").text()));

        // Collapse for subgrids
        var size = $("#main > #gridT > thead > tr > th").size();
        $("#main > #gridT > thead > tr").prepend("<th></th>");
        $("#main > #gridT > tbody > tr").each(function (i, el) {
            $(this).prepend(
                $("<td></td>")
                .addClass("expand")
                .addClass("hoverEff")
                .attr('title', "click for show/hide")
            );

            var table = $("table", this).parent().html();
            $(this).after("<tr><td></td><td style='padding:5px; margin:0px;' colspan='" + (size - 1) + "'>" + table + "</td></tr>");
            $("table", this).parent().remove();
            $(".hoverEff", this).live("click", function () {
                $(this).parent().closest("tr").next().slideToggle(100);
                $(this).toggleClass("expand collapse");
            });
        });

        //Default all subgrids to collapse mode
        $("#main > #gridT > tbody > tr td.expand").each(function (i, el) {
            $(this).toggleClass("expand collapse");
            $(this).parent().closest("tr").next().slideToggle(100);
        });

        // Removing the pseudo element for nesting.
        $('#gridT > thead > tr > th:nth-child(5)').remove();
    };

    function myFunction() {
        alert("before");
        
        // Replace the Status text with visual aids
        $(".statusCheck:contains('1')").html("<span class='oi agent-active' data-glyph='media-record'></span><span class='agent-active'>Active</span>");
        $(".statusCheck:contains('0')").html("<span class='oi agent-unresp' data-glyph='media-record'></span><span class='agent-unresp'>Not Responding</span>");


        // Pagination fix for styling
        var currentPage = $("td").contents().filter(function () {
            if (this.nodeType === 3) {
                return $.trim(this.textContent) !== "";
            }
            return false;
        }).get(0);
        $(currentPage).wrap('<a class="current" />');
        $(".current").text($.trim($(".current").text()));

        // Collapse for subgrids
        var size = $("#main > #gridT > thead > tr > th").size();        
        $("#main > #gridT > thead > tr").prepend("<th></th>");
        $("#main > #gridT > tbody > tr").each(function (i, el) {
            $(this).prepend(
                $("<td></td>")
                .addClass("expand")
                .addClass("hoverEff")
                .attr('title', "click for show/hide")
            );
                        
            var table = $("table", this).parent().html();
            $(this).after("<tr><td></td><td style='padding:5px; margin:0px;' colspan='" + (size - 1) + "'>" + table + "</td></tr>");
            $("table", this).parent().remove();
            $(".hoverEff", this).live("click", function () {
                $(this).parent().closest("tr").next().slideToggle(100);
                $(this).toggleClass("expand collapse");
            });
        });

        //Default all subgrids to collapse mode
        $("#main #gridT > tbody > tr td.expand").each(function (i, el) {
            $(this).toggleClass("expand collapse");
            $(this).parent().closest("tr").next().slideToggle(100);
        });

        // Removing the pseudo element for nesting.
         $('#gridT > thead > tr > th:nth-child(5)').remove();

        event.preventDefault();
       
    }
